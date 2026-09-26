//! OpenID Connect login for the web UI (authorization code flow with PKCE).
//!
//! The provider only authenticates; it never creates accounts or picks one by
//! name. Which account to enter is chosen on the login page, because one
//! person can be both: "as admin" requires membership in the configured admin
//! group; otherwise the user must have linked their provider identity (issuer
//! and subject) to their Jellyswarrm account while logged in with its
//! password, and SSO then logs them into exactly that account. Provider
//! usernames are never trusted, as users may be able to change them.

use std::time::Duration;

use anyhow::{anyhow, Context};
use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use axum_login::{tower_sessions::Session, AuthnBackend};
use axum_messages::Messages;
use openidconnect::{
    core::{CoreAuthenticationFlow, CoreClient, CoreGenderClaim, CoreProviderMetadata},
    reqwest, AdditionalClaims, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    EndpointMaybeSet, EndpointNotSet, EndpointSet, IssuerUrl, Nonce, OAuth2TokenResponse,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse, UserInfoClaims,
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::{
    config::OidcConfig,
    ui::{
        auth::{AuthSession, AuthenticatedUser, User, UserRole},
        is_same_origin,
    },
    AppState,
};

const FLOW_SESSION_KEY: &str = "oidc_flow";

type OidcClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

/// State kept in the UI session between the redirect and the callback.
#[derive(Serialize, Deserialize)]
struct OidcFlow {
    csrf_state: String,
    nonce: String,
    pkce_verifier: String,
    next: Option<String>,
    /// Set when the flow links the identity to this logged-in user instead of
    /// logging in.
    link_user_id: Option<String>,
    /// Log in as the admin (requires the admin group) rather than as the
    /// linked user. Chosen up front, because one person can be both.
    #[serde(default)]
    as_admin: bool,
    /// Started from the web player's login page: on success, continue to the
    /// page that signs the player in instead of the dashboard.
    #[serde(default)]
    player: bool,
}

#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    next: Option<String>,
    #[serde(default)]
    admin: bool,
    #[serde(default)]
    player: bool,
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct GroupsClaim {
    #[serde(default)]
    groups: Vec<String>,
}

impl AdditionalClaims for GroupsClaim {}

/// A provider identity whose ID token and userinfo have been verified.
struct VerifiedIdentity {
    issuer: String,
    subject: String,
    groups: Vec<String>,
    /// Only a name suggestion for a new account - never used to find one.
    preferred_username: Option<String>,
}

/// A login refused for a reason the user can act on; shown verbatim.
#[derive(Debug)]
struct LoginRefusal(&'static str);

impl std::fmt::Display for LoginRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for LoginRefusal {}

/// A usable account name from the provider's `preferred_username`.
fn account_name(preferred_username: Option<&str>) -> Option<String> {
    let name = preferred_username?.trim();
    (!name.is_empty() && name.chars().count() <= 64 && !name.chars().any(char::is_control))
        .then(|| name.to_string())
}

async fn oidc_client(config: &OidcConfig) -> anyhow::Result<(OidcClient, reqwest::Client)> {
    // No redirects: the provider's endpoints must answer directly (SSRF hygiene).
    let http_client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .build()
        .context("building OIDC HTTP client")?;

    let metadata = CoreProviderMetadata::discover_async(
        IssuerUrl::new(config.issuer_url.clone()).context("invalid oidc.issuer_url")?,
        &http_client,
    )
    .await
    .context("OIDC discovery failed")?;

    let client = CoreClient::from_provider_metadata(
        metadata,
        ClientId::new(config.client_id.clone()),
        config
            .client_secret
            .as_ref()
            .map(|secret| ClientSecret::new(secret.as_str().to_string())),
    )
    .set_redirect_uri(
        RedirectUrl::new(config.redirect_url.clone()).context("invalid oidc.redirect_url")?,
    );

    Ok((client, http_client))
}

/// Accept only same-origin paths as post-login targets. Whitespace and
/// control characters are refused because browsers strip them, which would
/// turn e.g. `/\t/evil.example` into the protocol-relative `//evil.example`.
fn safe_next(next: Option<String>, fallback: String) -> String {
    match next {
        Some(next)
            if next.starts_with('/')
                && !next.starts_with("//")
                && !next
                    .chars()
                    .any(|c| c == '\\' || c.is_whitespace() || c.is_control()) =>
        {
            next
        }
        _ => fallback,
    }
}

fn in_group(groups: &[String], group: Option<&str>) -> bool {
    group.is_some_and(|wanted| groups.iter().any(|group| group == wanted))
}

/// Start an authorization request and remember its secrets in the session.
async fn start_flow(
    state: &AppState,
    session: &Session,
    messages: Messages,
    next: Option<String>,
    link_user_id: Option<String>,
    as_admin: bool,
    player: bool,
) -> Response {
    let login_url = format!("/{}/login", state.get_ui_route().await);
    let Some(config) = state.config.read().await.oidc.clone() else {
        return Redirect::to(&login_url).into_response();
    };

    let (client, _) = match oidc_client(&config).await {
        Ok(client) => client,
        Err(e) => {
            warn!("OIDC unavailable: {e:#}");
            messages.error("Single sign-on is currently unavailable");
            return Redirect::to(&login_url).into_response();
        }
    };

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (auth_url, csrf_state, nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("groups".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    let flow = OidcFlow {
        csrf_state: csrf_state.secret().clone(),
        nonce: nonce.secret().clone(),
        pkce_verifier: pkce_verifier.secret().clone(),
        next,
        link_user_id,
        as_admin,
        player,
    };
    if let Err(e) = session.insert(FLOW_SESSION_KEY, flow).await {
        warn!("Failed to store OIDC flow state: {e}");
        messages.error("Single sign-on is currently unavailable");
        return Redirect::to(&login_url).into_response();
    }

    Redirect::to(auth_url.as_str()).into_response()
}

pub async fn login(
    State(state): State<AppState>,
    session: Session,
    messages: Messages,
    Query(LoginQuery {
        next,
        admin,
        player,
    }): Query<LoginQuery>,
) -> Response {
    // The admin has no media, so there is no admin login for the player.
    start_flow(
        &state,
        &session,
        messages,
        next,
        None,
        admin,
        player && !admin,
    )
    .await
}

/// Link the logged-in user's account to their provider identity.
pub async fn link(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    session: Session,
    messages: Messages,
    headers: HeaderMap,
) -> Response {
    if !is_same_origin(&headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    // The admin is a config account, not a user that can be linked.
    if user.role != UserRole::User {
        return StatusCode::FORBIDDEN.into_response();
    }
    start_flow(
        &state,
        &session,
        messages,
        None,
        Some(user.id),
        false,
        false,
    )
    .await
}

pub async fn callback(
    State(state): State<AppState>,
    mut auth_session: AuthSession,
    messages: Messages,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let ui_route = state.get_ui_route().await;
    let home = format!("/{ui_route}");
    let login_url = format!("/{ui_route}/login");

    // Always consume the flow state, so a callback URL can only be used once.
    let flow = auth_session
        .session
        .remove::<OidcFlow>(FLOW_SESSION_KEY)
        .await
        .ok()
        .flatten();
    let Some(flow) = flow else {
        warn!("OIDC callback without a pending flow in this session");
        messages.error("Single sign-on failed");
        return Redirect::to(&login_url).into_response();
    };

    let verified = verify_callback(&state, query, &flow).await;

    if let Some(link_user_id) = flow.link_user_id {
        let linked = match verified {
            Ok(identity) => link_identity(&state, &auth_session, &link_user_id, identity).await,
            Err(e) => Err(e),
        };
        return match linked {
            Ok(()) => {
                messages.success("Single sign-on linked to your account");
                Redirect::to(&home).into_response()
            }
            Err(e) => {
                warn!("OIDC link failed: {e:#}");
                messages.error("Linking single sign-on failed");
                Redirect::to(&home).into_response()
            }
        };
    }

    let logged_in = match verified {
        Ok(identity) => log_in(&state, &mut auth_session, identity, flow.as_admin).await,
        Err(e) => Err(e),
    };
    match logged_in {
        Ok(user) => {
            info!("OIDC login successful for {}", user.username);
            if flow.player {
                // One-shot permission for the player sign-in that follows.
                if let Err(e) = auth_session
                    .session
                    .insert(
                        crate::ui::user::player_login::PENDING_KEY,
                        chrono::Utc::now().timestamp(),
                    )
                    .await
                {
                    warn!("Failed to mark player sign-in as pending: {e}");
                }
                return Redirect::to(&format!("/{ui_route}/player-login")).into_response();
            }
            messages.success(format!("Successfully logged in as {}", user.username));
            Redirect::to(&safe_next(flow.next, home)).into_response()
        }
        Err(e) => {
            warn!("OIDC login failed: {e:#}");
            match e.downcast_ref::<LoginRefusal>() {
                Some(refusal) => messages.error(refusal.to_string()),
                None => messages.error("Single sign-on failed"),
            };
            Redirect::to(&login_url).into_response()
        }
    }
}

/// Check the callback against the stored flow, redeem the code and verify
/// the ID token (issuer, audience, expiry, signature, nonce) and userinfo.
async fn verify_callback(
    state: &AppState,
    query: CallbackQuery,
    flow: &OidcFlow,
) -> anyhow::Result<VerifiedIdentity> {
    if let Some(error) = query.error {
        return Err(anyhow!("provider returned error: {error:?}"));
    }
    let (Some(code), Some(returned_state)) = (query.code, query.state) else {
        return Err(anyhow!("callback without code or state"));
    };
    if returned_state != flow.csrf_state {
        return Err(anyhow!("state mismatch"));
    }

    let config = state
        .config
        .read()
        .await
        .oidc
        .clone()
        .ok_or_else(|| anyhow!("OIDC is not configured"))?;
    let (client, http_client) = oidc_client(&config).await?;

    let token_response = client
        .exchange_code(AuthorizationCode::new(code))?
        .set_pkce_verifier(PkceCodeVerifier::new(flow.pkce_verifier.clone()))
        .request_async(&http_client)
        .await
        .context("token exchange failed")?;

    let id_token = token_response
        .id_token()
        .ok_or_else(|| anyhow!("provider returned no ID token"))?;
    let id_claims = id_token
        .claims(&client.id_token_verifier(), &Nonce::new(flow.nonce.clone()))
        .context("ID token verification failed")?;

    // Passing the subject makes the library reject userinfo for anyone else.
    let user_info: UserInfoClaims<GroupsClaim, CoreGenderClaim> = client
        .user_info(
            token_response.access_token().clone(),
            Some(id_claims.subject().clone()),
        )?
        .request_async(&http_client)
        .await
        .context("userinfo request failed")?;

    Ok(VerifiedIdentity {
        issuer: id_claims.issuer().to_string(),
        subject: id_claims.subject().to_string(),
        groups: user_info.additional_claims().groups.clone(),
        preferred_username: user_info
            .preferred_username()
            .map(|name| name.as_str().to_string()),
    })
}

async fn log_in(
    state: &AppState,
    auth_session: &mut AuthSession,
    identity: VerifiedIdentity,
    as_admin: bool,
) -> anyhow::Result<User> {
    let (admin_group, user_group) = state
        .config
        .read()
        .await
        .oidc
        .as_ref()
        .map(|config| (config.admin_group.clone(), config.user_group.clone()))
        .unwrap_or_default();

    let user_id = if as_admin {
        if !in_group(&identity.groups, admin_group.as_deref()) {
            return Err(LoginRefusal("Your account is not allowed to sign in as admin").into());
        }
        "admin".to_string()
    } else if let Some(user_id) = state
        .user_authorization
        .get_user_id_by_oidc_identity(&identity.issuer, &identity.subject)
        .await?
    {
        user_id
    } else if in_group(&identity.groups, user_group.as_deref()) {
        let name = account_name(identity.preferred_username.as_deref()).ok_or(LoginRefusal(
            "Your single sign-on account has no usable username",
        ))?;
        match state
            .user_authorization
            .create_sso_user(&name, &identity.issuer, &identity.subject)
            .await
        {
            Ok(user) => user.id,
            // Never attach to an existing account by name.
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                return Err(LoginRefusal(
                    "An account with your username already exists. Sign in with its password and link single sign-on under Profile.",
                )
                .into());
            }
            Err(e) => return Err(e.into()),
        }
    } else {
        warn!(
            "identity {} at {} is not linked and not in the user group",
            identity.subject, identity.issuer
        );
        return Err(LoginRefusal(
            "Your single sign-on account is not linked to a Jellyswarrm account. Sign in with your password and link it under Profile.",
        )
        .into());
    };

    let user = auth_session
        .backend
        .get_user(&user_id)
        .await?
        .ok_or_else(|| anyhow!("user '{user_id}' vanished during login"))?;
    // Rotate the session id even when another user was logged in before.
    auth_session.session.cycle_id().await?;
    auth_session.login(&user).await?;
    Ok(user)
}

async fn link_identity(
    state: &AppState,
    auth_session: &AuthSession,
    link_user_id: &str,
    identity: VerifiedIdentity,
) -> anyhow::Result<()> {
    // The flow must finish in the session of the user who started it.
    let current = auth_session.user.as_ref().map(|user| user.id.as_str());
    if current != Some(link_user_id) {
        return Err(anyhow!("link flow finished by a different or no user"));
    }

    state
        .user_authorization
        .link_oidc_identity(link_user_id, &identity.issuer, &identity.subject)
        .await
        .context("identity is already linked to another user")?;
    info!(
        "Linked OIDC identity {} at {} to user {}",
        identity.subject, identity.issuer, link_user_id
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_must_be_a_same_origin_path() {
        let fallback = || "/ui".to_string();
        assert_eq!(safe_next(Some("/ui/user".into()), fallback()), "/ui/user");
        assert_eq!(safe_next(Some("//evil.example".into()), fallback()), "/ui");
        assert_eq!(safe_next(Some("/\\evil.example".into()), fallback()), "/ui");
        assert_eq!(
            safe_next(Some("/\t/evil.example".into()), fallback()),
            "/ui"
        );
        assert_eq!(
            safe_next(Some("/\n/evil.example".into()), fallback()),
            "/ui"
        );
        assert_eq!(
            safe_next(Some("https://evil.example".into()), fallback()),
            "/ui"
        );
        assert_eq!(safe_next(None, fallback()), "/ui");
    }

    #[test]
    fn only_admin_group_members_are_admin() {
        let groups = vec!["family".to_string(), "jellyswarrm-admins".to_string()];
        assert!(in_group(&groups, Some("jellyswarrm-admins")));
        assert!(!in_group(&groups, Some("other")));
        // Without an admin group nobody becomes admin via OIDC.
        assert!(!in_group(&groups, None));
    }

    #[test]
    fn account_names_are_trimmed_and_bounded() {
        assert_eq!(account_name(Some(" alice ")), Some("alice".to_string()));
        assert_eq!(account_name(Some("  ")), None);
        assert_eq!(account_name(None), None);
        assert_eq!(account_name(Some("bad\nname")), None);
        assert_eq!(account_name(Some(&"x".repeat(65))), None);
        assert!(account_name(Some(&"x".repeat(64))).is_some());
    }
}
