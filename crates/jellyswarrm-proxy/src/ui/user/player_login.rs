//! Sign the Jellyfin web player in after single sign-on.
//!
//! The player's login page offers "Sign in with SSO", which runs the
//! dashboard's OIDC flow and ends here. This page signs in the browser's web
//! client: it asks for a session for the player's own device and stores it
//! where the web client keeps its login, so the player opens signed in.

use askama::Template;
use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
    Json,
};
use axum_login::tower_sessions::Session;
use serde::Deserialize;
use serde_json::json;
use tracing::{error, info, warn};

use crate::{
    handlers::quick_connect::{sign_in_device, DeviceSignInError},
    models::Authorization,
    ui::{
        auth::{AuthenticatedUser, UserRole},
        is_same_origin, JELLYFIN_UI_VERSION,
    },
    AppState,
};

/// Set by the OIDC callback when the flow started from the player; consumed by
/// [`session`]. Without it, any site could navigate a signed-in user to the
/// page and quietly open upstream sessions.
pub(crate) const PENDING_KEY: &str = "player_login_pending";
const PENDING_TTL_SECS: i64 = 300;
/// The web client's own client name (jellyfin-web's apphost).
const WEB_CLIENT: &str = "Jellyfin Web";

#[derive(Template)]
#[template(path = "player_login.html")]
struct PlayerLoginTemplate {
    ui_route: String,
    /// JSON for the page script; `</` is escaped so it cannot end the tag.
    config_json: String,
}

pub async fn page(State(state): State<AppState>) -> Response {
    let ui_route = state.get_ui_route().await;
    let web_base = state
        .get_url_prefix()
        .await
        .map(|prefix| format!("/{prefix}"))
        .unwrap_or_default();
    let app_version = JELLYFIN_UI_VERSION
        .as_ref()
        .map(|v| v.version.clone())
        .unwrap_or_else(|| "unknown".to_string());
    let config_json = json!({
        "sessionUrl": format!("/{ui_route}/player-login/session"),
        "webBase": web_base,
        "appVersion": app_version,
    })
    .to_string()
    .replace("</", "<\\/");

    match (PlayerLoginTemplate {
        ui_route,
        config_json,
    })
    .render()
    {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            error!("Failed to render player login page: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Template error").into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct PlayerSessionRequest {
    /// The plain id from the web client's localStorage (`_deviceId2`); the
    /// client sends it URL-encoded, which the header parser decodes again.
    device_id: String,
    device_name: String,
    app_version: String,
}

/// Values end up in Authorization headers sent upstream later.
fn header_safe(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(|c| c == '"' || c.is_control())
}

fn refuse(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

/// Open a session for the player's device and return it the way the web
/// client's own login would.
pub async fn session(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    session: Session,
    headers: HeaderMap,
    Json(request): Json<PlayerSessionRequest>,
) -> Response {
    if !is_same_origin(&headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    if user.role != UserRole::User {
        return refuse(
            StatusCode::FORBIDDEN,
            "The admin account has no media to play",
        );
    }

    let pending = session.remove::<i64>(PENDING_KEY).await.ok().flatten();
    if pending.is_none_or(|started| chrono::Utc::now().timestamp() - started > PENDING_TTL_SECS) {
        return refuse(
            StatusCode::FORBIDDEN,
            "Start again from the player's \"Sign in with SSO\" button",
        );
    }

    if ![
        &request.device_id,
        &request.device_name,
        &request.app_version,
    ]
    .into_iter()
    .all(|value| header_safe(value))
    {
        return refuse(StatusCode::BAD_REQUEST, "Invalid device information");
    }

    let db_user = match state.user_authorization.get_user_by_id(&user.id).await {
        Ok(Some(db_user)) => db_user,
        Ok(None) => return refuse(StatusCode::UNAUTHORIZED, "Account not found"),
        Err(e) => {
            error!("Failed to load user {}: {}", user.id, e);
            return refuse(StatusCode::INTERNAL_SERVER_ERROR, "Database error");
        }
    };

    let authorization = Authorization {
        client: WEB_CLIENT.to_string(),
        device: request.device_name,
        device_id: request.device_id,
        version: request.app_version,
        token: None,
    };

    match sign_in_device(&state, &db_user, authorization).await {
        Ok(response) => {
            info!("Signed in the web player for {} via SSO", user.username);
            let (mut response_headers, body) = crate::sessions::authentication_response(response);
            response_headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            (response_headers, body).into_response()
        }
        Err(e) => {
            warn!("Player sign-in for {} failed: {:?}", user.username, e);
            let message = match e {
                DeviceSignInError::NoServers => "No servers are configured",
                DeviceSignInError::NoConnectedServers => {
                    "Connect a server first: dashboard -> Servers -> Quick Connect"
                }
                DeviceSignInError::AllServersRefused => {
                    "No connected server accepted the sign-in - reconnect it in the dashboard"
                }
                DeviceSignInError::Internal => "Sign-in failed",
            };
            refuse(e.status(), message)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::MediaStreamingMode,
        handlers::quick_connect::tests::create_test_app_state,
        ui::auth::User,
        user_authorization_service::{Device, LocalCredential},
    };
    use axum_login::tower_sessions::MemoryStore;
    use std::sync::Arc;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    /// A user with a token-backed mapping to a mocked upstream that mints
    /// device sessions through Quick Connect.
    async fn setup() -> (
        AppState,
        crate::user_authorization_service::User,
        MockServer,
    ) {
        let state = create_test_app_state().await;
        let upstream = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/QuickConnect/Initiate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "Secret": "s", "Code": "123456", "Authenticated": false
            })))
            .mount(&upstream)
            .await;
        Mock::given(method("POST"))
            .and(path("/QuickConnect/Authorize"))
            .respond_with(ResponseTemplate::new(200).set_body_json(true))
            .mount(&upstream)
            .await;
        Mock::given(method("POST"))
            .and(path("/Users/AuthenticateWithQuickConnect"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "User": {"Name": "alice", "ServerId": "up", "Id": "up-user",
                         "Policy": {"IsAdministrator": false, "SyncPlayAccess": "None"}},
                "SessionInfo": {"UserId": "up-user", "UserName": "alice", "ServerId": "up"},
                "AccessToken": "device-token",
                "ServerId": "up"
            })))
            .mount(&upstream)
            .await;

        let server_id = state
            .server_storage
            .add_server("Upstream", &upstream.uri(), 100, MediaStreamingMode::Proxy)
            .await
            .unwrap();
        let server = state
            .server_storage
            .get_server_by_id(server_id)
            .await
            .unwrap()
            .unwrap();
        let user = state
            .user_authorization
            .create_sso_user("alice", "https://idp.example", "sub-a")
            .await
            .unwrap();
        state
            .user_authorization
            .add_token_server_mapping(
                &user.id,
                server.id,
                server.url.as_str(),
                "alice",
                "base-token",
                &state.upstream_token_key().await,
            )
            .await
            .unwrap();
        (state, user, upstream)
    }

    fn ui_user(user: &crate::user_authorization_service::User, role: UserRole) -> User {
        User {
            id: user.id.clone(),
            username: user.original_username.clone(),
            local_credential: LocalCredential::Passwordless,
            role,
        }
    }

    fn same_origin() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("host", "swarm.example".parse().unwrap());
        headers.insert("origin", "https://swarm.example".parse().unwrap());
        headers
    }

    async fn pending_session() -> Session {
        let session = Session::new(None, Arc::new(MemoryStore::default()), None);
        session
            .insert(PENDING_KEY, chrono::Utc::now().timestamp())
            .await
            .unwrap();
        session
    }

    // jellyfin-web device ids are base64 and usually contain + or /. The web
    // client sends them URL-encoded; the header parser decodes them, so the
    // session must be stored under the plain id.
    const DEVICE_ID: &str = "TW96aWxsYS81LjA+fDE3/g11";
    const ENCODED_DEVICE_ID: &str = "TW96aWxsYS81LjA%2BfDE3%2Fg11";

    fn request() -> PlayerSessionRequest {
        PlayerSessionRequest {
            device_id: DEVICE_ID.to_string(),
            device_name: "Chrome".to_string(),
            app_version: "12.1.0".to_string(),
        }
    }

    #[tokio::test]
    async fn signs_the_player_in_as_the_web_client_would() {
        let (state, user, _upstream) = setup().await;
        let session_store = pending_session().await;

        let response = session(
            State(state.clone()),
            AuthenticatedUser(ui_user(&user, UserRole::User)),
            session_store.clone(),
            same_origin(),
            Json(request()),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["AccessToken"], user.virtual_key);
        assert_eq!(body["User"]["Id"], user.id);
        // One-shot: the permission is consumed.
        assert!(session_store
            .get::<i64>(PENDING_KEY)
            .await
            .unwrap()
            .is_none());

        // The web client's next request finds the session through the real
        // header parser.
        let later = Authorization::parse(&format!(
            "MediaBrowser Client=\"Jellyfin Web\", Device=\"Chrome\", DeviceId=\"{ENCODED_DEVICE_ID}\", Version=\"12.1.0\", Token=\"{}\"",
            user.virtual_key
        ))
        .unwrap();
        let sessions = state
            .user_authorization
            .get_user_sessions(
                &user.id,
                Some(Device {
                    client: later.client,
                    device: later.device,
                    device_id: later.device_id,
                    version: later.version,
                }),
            )
            .await
            .unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].0.jellyfin_token, "device-token");
    }

    #[tokio::test]
    async fn refuses_without_a_pending_sso_login() {
        let (state, user, _upstream) = setup().await;
        let response = session(
            State(state),
            AuthenticatedUser(ui_user(&user, UserRole::User)),
            Session::new(None, Arc::new(MemoryStore::default()), None),
            same_origin(),
            Json(request()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn refuses_cross_origin_and_admin() {
        let (state, user, _upstream) = setup().await;
        let response = session(
            State(state.clone()),
            AuthenticatedUser(ui_user(&user, UserRole::User)),
            pending_session().await,
            HeaderMap::new(),
            Json(request()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let response = session(
            State(state),
            AuthenticatedUser(ui_user(&user, UserRole::Admin)),
            pending_session().await,
            same_origin(),
            Json(request()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn header_values_are_bounded() {
        assert!(header_safe("TW96aWxsYS81LjA+fDE3/g11"));
        assert!(!header_safe(""));
        assert!(!header_safe("a\"b"));
        assert!(!header_safe("a\nb"));
        assert!(!header_safe(&"x".repeat(257)));
    }
}
