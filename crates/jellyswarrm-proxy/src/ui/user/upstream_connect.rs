//! Connect a server through its own Quick Connect instead of a password.
//!
//! Jellyswarrm starts a Quick Connect request on the upstream server and shows
//! the code; the user approves it in that server's web UI (where they can sign
//! in however that server allows, single sign-on included). Jellyswarrm then
//! redeems the request and keeps the resulting upstream token for the user's
//! mapping. No password is ever entered or stored.

use askama::Template;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
};
use axum_login::tower_sessions::Session;
use jellyfin_api::{error::Error as JellyfinApiError, JellyfinClient};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::{
    handlers::quick_connect::upstream_client_info,
    server_id::ServerId,
    server_storage::Server,
    ui::{
        auth::{AuthenticatedUser, User, UserRole},
        is_same_origin,
    },
    AppState,
};

const PENDING_KEY: &str = "upstream_quick_connect";
/// Upstream Quick Connect requests expire after ten minutes.
const PENDING_TTL_SECS: i64 = 600;

#[derive(Serialize, Deserialize)]
struct PendingUpstreamConnect {
    server_id: i64,
    secret: String,
    code: String,
    started_at: i64,
}

#[derive(Template)]
#[template(path = "user/upstream_quick_connect.html")]
struct UpstreamQuickConnectTemplate {
    error: Option<String>,
    code: String,
    server_name: String,
    approve_url: String,
    poll_url: String,
}

fn render(template: UpstreamQuickConnectTemplate) -> Response {
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            error!("Failed to render upstream Quick Connect template: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Template error").into_response()
        }
    }
}

fn error_fragment(message: impl Into<String>) -> Response {
    render(UpstreamQuickConnectTemplate {
        error: Some(message.into()),
        code: String::new(),
        server_name: String::new(),
        approve_url: String::new(),
        poll_url: String::new(),
    })
}

async fn pending_fragment(state: &AppState, server: &Server, code: &str) -> Response {
    render(UpstreamQuickConnectTemplate {
        error: None,
        code: code.to_string(),
        server_name: server.name.clone(),
        approve_url: format!(
            "{}/web/#/quickconnect",
            server.url.as_str().trim_end_matches('/')
        ),
        poll_url: format!(
            "/{}/user/servers/{}/quick-connect",
            state.get_ui_route().await,
            server.id
        ),
    })
}

/// A fresh client with the user's upstream identity - never a cached one,
/// since evicted cached clients log out and would revoke the token.
fn upstream_client(state: &AppState, user: &User, server: &Server) -> Option<JellyfinClient> {
    JellyfinClient::new_with_client(
        server.url.as_str(),
        upstream_client_info(&user.id, &user.username, server.id),
        state.reqwest_client.clone(),
    )
    .map_err(|e| error!("Failed to create upstream client: {}", e))
    .ok()
}

async fn find_server(state: &AppState, server_id: ServerId) -> Result<Server, Response> {
    match state.server_storage.get_server_by_id(server_id).await {
        Ok(Some(server)) => Ok(server),
        Ok(None) => Err(error_fragment("Server not found")),
        Err(e) => {
            error!("Failed to get server: {}", e);
            Err(error_fragment("Database error"))
        }
    }
}

/// Start a Quick Connect request on the upstream server.
pub async fn start(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    session: Session,
    headers: HeaderMap,
    Path(server_id): Path<ServerId>,
) -> Response {
    if !is_same_origin(&headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    if user.role != UserRole::User {
        return error_fragment("The admin account cannot connect servers");
    }
    let server = match find_server(&state, server_id).await {
        Ok(server) => server,
        Err(response) => return response,
    };
    let Some(client) = upstream_client(&state, &user, &server) else {
        return error_fragment("Client error");
    };

    let pending = match client.quick_connect_initiate().await {
        Ok(pending) => pending,
        Err(JellyfinApiError::Unauthorized | JellyfinApiError::Forbidden) => {
            return error_fragment(format!(
                "Quick Connect is disabled on {}. Ask its admin to enable it, or connect with a password.",
                server.name
            ));
        }
        Err(e) => {
            warn!(
                "Upstream Quick Connect initiate failed for {}: {}",
                server.name, e
            );
            return error_fragment(format!("{} is not reachable", server.name));
        }
    };

    let record = PendingUpstreamConnect {
        server_id: server.id.as_i64(),
        secret: pending.secret,
        code: pending.code.clone(),
        started_at: chrono::Utc::now().timestamp(),
    };
    if let Err(e) = session.insert(PENDING_KEY, record).await {
        error!("Failed to store pending upstream Quick Connect: {}", e);
        return error_fragment("Session error");
    }

    pending_fragment(&state, &server, &pending.code).await
}

/// Poll the pending request; once approved upstream, store the token.
pub async fn status(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    session: Session,
    Path(server_id): Path<ServerId>,
) -> Response {
    let pending = session
        .get::<PendingUpstreamConnect>(PENDING_KEY)
        .await
        .ok()
        .flatten()
        .filter(|pending| pending.server_id == server_id.as_i64());
    let Some(pending) = pending else {
        return error_fragment("No Quick Connect request in progress - start again");
    };

    if chrono::Utc::now().timestamp() - pending.started_at > PENDING_TTL_SECS {
        let _ = session.remove::<PendingUpstreamConnect>(PENDING_KEY).await;
        return error_fragment("The code expired - start again");
    }

    let server = match find_server(&state, server_id).await {
        Ok(server) => server,
        Err(response) => return response,
    };
    let Some(client) = upstream_client(&state, &user, &server) else {
        return error_fragment("Client error");
    };

    match client.quick_connect_state(&pending.secret).await {
        Ok(result) if result.authenticated => {}
        Ok(_) => return pending_fragment(&state, &server, &pending.code).await,
        Err(JellyfinApiError::NotFound) => {
            let _ = session.remove::<PendingUpstreamConnect>(PENDING_KEY).await;
            return error_fragment("The code expired - start again");
        }
        Err(e) => {
            // Transient: keep polling.
            warn!(
                "Upstream Quick Connect state check failed for {}: {}",
                server.name, e
            );
            return pending_fragment(&state, &server, &pending.code).await;
        }
    }

    let _ = session.remove::<PendingUpstreamConnect>(PENDING_KEY).await;
    let upstream = match client
        .authenticate_with_quick_connect(&pending.secret)
        .await
    {
        Ok(upstream) => upstream,
        Err(e) => {
            warn!(
                "Upstream Quick Connect redeem failed for {}: {}",
                server.name, e
            );
            return error_fragment("Approval could not be redeemed - start again");
        }
    };

    let token_key = state.upstream_token_key().await;
    if let Err(e) = state
        .user_authorization
        .add_token_server_mapping(
            &user.id,
            server.id,
            server.url.as_str(),
            &upstream.user.name,
            &upstream.access_token,
            &token_key,
        )
        .await
    {
        error!("Failed to store token mapping: {}", e);
        return error_fragment("Database error");
    }
    info!(
        "User {} connected server {} through Quick Connect as '{}'",
        user.username, server.name, upstream.user.name
    );

    let mut response = StatusCode::OK.into_response();
    if let Ok(target) = HeaderValue::from_str(&format!("/{}", state.get_ui_route().await)) {
        response.headers_mut().insert("HX-Redirect", target);
    }
    response
}
