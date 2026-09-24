//! Approve a Quick Connect code from the web UI.
//!
//! This is the bridge for single sign-on: a native client shows a code, the
//! user signs in here (password or OIDC) and approves it, and the client is
//! then logged in with the user's existing server mappings.

use askama::Template;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    Form,
};
use serde::Deserialize;
use tracing::{error, info};

use crate::{
    ui::{
        auth::{AuthenticatedUser, UserRole},
        is_same_origin,
    },
    AppState,
};

#[derive(Template)]
#[template(path = "user/quick_connect.html")]
pub struct QuickConnectTemplate {
    pub ui_route: String,
}

#[derive(Deserialize)]
pub struct QuickConnectForm {
    pub code: String,
}

fn alert(ok: bool, text: &str) -> Html<String> {
    let (color, icon) = if ok {
        ("#2e7d32", "fa-check-circle")
    } else {
        ("#c62828", "fa-exclamation-circle")
    };
    Html(format!(
        r#"<div role="alert" style="background-color: {color}; color: white; padding: 0.75rem; border-radius: 0.25rem;">
            <i class="fas {icon}" style="margin-right: 0.5rem;"></i> {text}
        </div>"#
    ))
}

pub async fn get_quick_connect(State(state): State<AppState>) -> impl IntoResponse {
    let template = QuickConnectTemplate {
        ui_route: state.get_ui_route().await,
    };
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            error!("Failed to render Quick Connect template: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Template error").into_response()
        }
    }
}

pub async fn post_quick_connect(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    headers: HeaderMap,
    Form(form): Form<QuickConnectForm>,
) -> Response {
    // One approval hands a device the user's account, so refuse cross-origin
    // submissions (SameSite=Lax still lets sibling subdomains through).
    if !is_same_origin(&headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    // The admin is a config account without media access or server mappings.
    if user.role != UserRole::User {
        return alert(false, "Quick Connect needs a user account, not the admin").into_response();
    }

    let code = form.code.trim();
    let approved = state.quick_connect.update_session_by_code(code, |session| {
        session.authenticated = true;
        session.user_id = Some(user.id.clone());
    });

    if approved {
        info!(
            "Approved Quick Connect code via web UI for {}",
            user.username
        );
        alert(
            true,
            "Device approved. It will sign in within a few seconds.",
        )
        .into_response()
    } else {
        alert(false, "Unknown or expired code").into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        handlers::quick_connect::QuickConnectSession, ui::auth::User,
        user_authorization_service::LocalCredential,
    };

    fn ui_user(id: &str, role: UserRole) -> User {
        User {
            id: id.to_string(),
            username: "anna".to_string(),
            local_credential: LocalCredential::Passwordless,
            role,
        }
    }

    fn same_origin() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("host", "swarm.example:3000".parse().unwrap());
        headers.insert("origin", "https://swarm.example:3000".parse().unwrap());
        headers
    }

    fn pending_session(state: &AppState) -> QuickConnectSession {
        state.quick_connect.store_session(QuickConnectSession::new(
            "99999999-9999-4999-8999-999999999999".to_string(),
            "314159".to_string(),
            "device".to_string(),
            "TV".to_string(),
            "App".to_string(),
            "1.0".to_string(),
        ))
    }

    #[tokio::test]
    async fn user_approves_a_pending_code() {
        let state = crate::handlers::quick_connect::tests::create_test_app_state().await;
        let pending = pending_session(&state);

        let response = post_quick_connect(
            State(state.clone()),
            AuthenticatedUser(ui_user("user-1", UserRole::User)),
            same_origin(),
            Form(QuickConnectForm {
                code: format!(" {} ", pending.code),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let session = state.quick_connect.get_session(&pending.secret).unwrap();
        assert!(session.authenticated);
        assert_eq!(session.user_id.as_deref(), Some("user-1"));
    }

    #[tokio::test]
    async fn admin_cannot_approve() {
        let state = crate::handlers::quick_connect::tests::create_test_app_state().await;
        let pending = pending_session(&state);

        post_quick_connect(
            State(state.clone()),
            AuthenticatedUser(ui_user("admin", UserRole::Admin)),
            same_origin(),
            Form(QuickConnectForm {
                code: pending.code.clone(),
            }),
        )
        .await;

        let session = state.quick_connect.get_session(&pending.secret).unwrap();
        assert!(!session.authenticated);
        assert!(session.user_id.is_none());
    }

    #[tokio::test]
    async fn secret_is_not_accepted_as_code() {
        let state = crate::handlers::quick_connect::tests::create_test_app_state().await;
        let pending = pending_session(&state);

        post_quick_connect(
            State(state.clone()),
            AuthenticatedUser(ui_user("user-1", UserRole::User)),
            same_origin(),
            Form(QuickConnectForm {
                code: pending.secret.clone(),
            }),
        )
        .await;

        assert!(
            !state
                .quick_connect
                .get_session(&pending.secret)
                .unwrap()
                .authenticated
        );
    }

    #[tokio::test]
    async fn cross_origin_submission_is_refused() {
        let state = crate::handlers::quick_connect::tests::create_test_app_state().await;
        let pending = pending_session(&state);
        let mut headers = HeaderMap::new();
        headers.insert("host", "swarm.example:3000".parse().unwrap());
        headers.insert("origin", "https://evil.example".parse().unwrap());

        let response = post_quick_connect(
            State(state.clone()),
            AuthenticatedUser(ui_user("user-1", UserRole::User)),
            headers,
            Form(QuickConnectForm {
                code: pending.code.clone(),
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(
            !state
                .quick_connect
                .get_session(&pending.secret)
                .unwrap()
                .authenticated
        );
    }
}
