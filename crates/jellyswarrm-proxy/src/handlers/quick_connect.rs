use crate::{
    encryption::HashedPassword,
    models::{AuthenticateResponse, Authorization, SyncPlayUserAccessType},
    AppState,
};
use axum::{
    extract::{Query, State},
    http::HeaderMap,
    Json,
};
use chrono::{DateTime, Duration, Utc};
use hyper::StatusCode;
use jellyfin_api::{error::Error as JellyfinApiError, ClientInfo, JellyfinClient};
use jellyswarrm_macros::multi_case_struct;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
};
use tracing::{debug, info, warn};
use uuid::Uuid;

#[multi_case_struct(pascal, camel)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuickConnectSession {
    pub authenticated: bool,
    pub secret: String,
    pub code: String,
    pub device_id: String,
    pub device_name: String,
    pub app_name: String,
    pub app_version: String,
    pub date_added: DateTime<Utc>,
    #[serde(skip)]
    pub user_id: Option<String>,
    #[serde(skip)]
    pub expires_at: DateTime<Utc>,
}

impl QuickConnectSession {
    pub fn new(
        secret: String,
        code: String,
        device_id: String,
        device_name: String,
        app_name: String,
        app_version: String,
    ) -> Self {
        let now = Utc::now();
        Self {
            authenticated: false,
            secret,
            code,
            device_id,
            device_name,
            app_name,
            app_version,
            date_added: now,
            user_id: None,
            expires_at: now + Duration::minutes(10),
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

#[multi_case_struct(pascal, camel)]
#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    pub code: String,
    pub user_id: Option<String>,
}

#[multi_case_struct(pascal, camel)]
#[derive(Debug, Deserialize)]
pub struct ConnectQuery {
    pub secret: String,
}

#[multi_case_struct(pascal, camel)]
#[derive(Debug, Deserialize)]
pub struct QuickConnectAuthenticateRequest {
    pub secret: String,
}

pub struct QuickConnectStorage {
    sessions: Arc<Mutex<HashMap<String, QuickConnectSession>>>,
}

impl Default for QuickConnectStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl QuickConnectStorage {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Store a session, returning it with its final code.
    ///
    /// A session is indexed under both its secret and its code so it can be
    /// looked up by either. Because clients pick their own moment to poll, the
    /// code must stay unique across all live sessions: otherwise a second
    /// `Initiate` could repoint a victim's pending code at the attacker's
    /// session, and approving "their" code would approve the attacker's. The
    /// code is therefore (re)generated under the lock until it is free, so the
    /// caller must use the returned session's code, not the one it passed in.
    pub fn store_session(&self, mut session: QuickConnectSession) -> QuickConnectSession {
        let mut sessions = self.sessions_lock();
        while sessions
            .get(&session.code)
            .is_some_and(|existing| !existing.is_expired())
        {
            session.code = generate_code();
        }
        sessions.insert(session.secret.clone(), session.clone());
        sessions.insert(session.code.clone(), session.clone());
        session
    }

    /// Look up a session by its secret.
    ///
    /// A session is also indexed under its 6-digit code, but the code must
    /// never be accepted as a secret: it is short, guessable and meant to be
    /// shown to the user, while the secret authenticates the polling device.
    /// The match is only honoured when the stored entry's secret equals the
    /// key, which rejects a code passed in the secret's place (a code can never
    /// equal a UUID secret).
    pub fn get_session(&self, secret: &str) -> Option<QuickConnectSession> {
        let mut sessions = self.sessions_lock();

        if let Some(session) = sessions.get(secret) {
            if session.is_expired() {
                let stored_secret = session.secret.clone();
                let code = session.code.clone();
                sessions.remove(&stored_secret);
                sessions.remove(&code);
                return None;
            }

            if session.secret != secret {
                return None;
            }

            return Some(session.clone());
        }

        None
    }

    /// Approve/update a session addressed by its 6-digit code.
    ///
    /// Mirrors [`Self::get_session`]: a secret must never be accepted here in
    /// the code's place, so the update only applies when the stored entry's
    /// code equals the key.
    pub fn update_session_by_code(
        &self,
        code: &str,
        mut updater: impl FnMut(&mut QuickConnectSession),
    ) -> bool {
        let mut sessions = self.sessions_lock();

        if let Some(session) = sessions.get(code).cloned() {
            if session.is_expired() {
                let secret = session.secret.clone();
                sessions.remove(&secret);
                sessions.remove(code);
                return false;
            }

            if session.code != code {
                return false;
            }

            let mut updated_session = session;
            updater(&mut updated_session);

            let secret = updated_session.secret.clone();
            sessions.insert(secret, updated_session.clone());
            sessions.insert(code.to_string(), updated_session);
            return true;
        }

        false
    }

    /// Remove a session addressed by its secret.
    ///
    /// As in [`Self::get_session`], a code must not stand in for a secret: a
    /// looked-up entry whose secret differs from the key is a code hit and is
    /// left untouched.
    pub fn remove_session(&self, secret: &str) -> Option<QuickConnectSession> {
        let mut sessions = self.sessions_lock();

        if sessions.get(secret).is_some_and(|s| s.secret != secret) {
            return None;
        }

        if let Some(session) = sessions.remove(secret) {
            sessions.remove(&session.code);
            return Some(session);
        }

        None
    }

    pub fn cleanup_expired(&self) -> usize {
        let mut sessions = self.sessions_lock();
        let mut expired = Vec::new();

        for session in sessions.values() {
            if session.is_expired() {
                expired.push((session.secret.clone(), session.code.clone()));
            }
        }

        for (secret, code) in &expired {
            sessions.remove(secret);
            sessions.remove(code);
        }

        expired.len()
    }

    pub fn start_cleanup_task(storage: QuickConnectStorage) {
        use std::time::Duration as StdDuration;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(StdDuration::from_secs(60));
            loop {
                interval.tick().await;
                let cleaned = storage.cleanup_expired();
                if cleaned > 0 {
                    warn!("Cleaned up {} expired Quick Connect sessions", cleaned);
                }
            }
        });
    }

    fn sessions_lock(&self) -> MutexGuard<'_, HashMap<String, QuickConnectSession>> {
        self.sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Clone for QuickConnectStorage {
    fn clone(&self) -> Self {
        Self {
            sessions: Arc::clone(&self.sessions),
        }
    }
}

fn generate_code() -> String {
    let mut rng = rand::rng();
    (0..6)
        .map(|_| char::from(b'0' + rng.random_range(0..10) as u8))
        .collect::<String>()
}

fn parse_authorization_from_headers(headers: &HeaderMap) -> Option<Authorization> {
    if let Some(header) = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
    {
        match Authorization::parse_with_legacy(header, true) {
            Ok(auth) => return Some(auth),
            Err(e) => warn!("Failed to parse Authorization header: {}", e),
        }
    }

    if let Some(header) = headers
        .get("x-emby-authorization")
        .and_then(|value| value.to_str().ok())
    {
        match Authorization::parse_with_legacy(header, true) {
            Ok(auth) => return Some(auth),
            Err(e) => warn!("Failed to parse X-Emby-Authorization header: {}", e),
        }
    }

    None
}

fn parse_client_info(headers: &HeaderMap) -> (String, String, String, String) {
    if let Some(auth) = parse_authorization_from_headers(headers) {
        return (auth.device_id, auth.device, auth.client, auth.version);
    }

    (
        Uuid::new_v4().to_string(),
        "Unknown Device".to_string(),
        "Unknown App".to_string(),
        "1.0.0".to_string(),
    )
}

fn is_android_tv_client(client: &str) -> bool {
    client.to_ascii_lowercase().contains("android tv")
}

fn normalize_android_tv_user_id(user_id: &str) -> String {
    Uuid::parse_str(user_id)
        .map(|id| id.hyphenated().to_string())
        .unwrap_or_else(|_| user_id.to_string())
}

fn derive_android_tv_user_device_id(base_device_id: &str, user_id: &str) -> String {
    let normalized_user_id = normalize_android_tv_user_id(user_id);
    let mut hasher = Sha1::new();
    hasher.update(base_device_id.as_bytes());
    hasher.update(b"+");
    hasher.update(normalized_user_id.as_bytes());
    hex::encode(hasher.finalize())
}

fn effective_quick_connect_authorization(
    headers: &HeaderMap,
    session: &QuickConnectSession,
    user_id: &str,
) -> Authorization {
    let request_authorization = parse_authorization_from_headers(headers);

    let mut authorization = request_authorization.unwrap_or_else(|| {
        warn!(
            "Quick Connect authenticate request missing parseable authorization header, using initiate metadata"
        );
        Authorization {
            client: session.app_name.clone(),
            device: session.device_name.clone(),
            device_id: session.device_id.clone(),
            version: session.app_version.clone(),
            token: None,
        }
    });

    authorization.token = None;

    if is_android_tv_client(&authorization.client) && !authorization.device_id.is_empty() {
        let original_device_id = authorization.device_id.clone();
        authorization.device_id =
            derive_android_tv_user_device_id(&authorization.device_id, user_id);
        debug!(
            "Derived Android TV user-scoped device id for Quick Connect: {} -> {}",
            original_device_id, authorization.device_id
        );
    }

    authorization
}

pub async fn handle_quick_connect_enabled() -> Result<Json<bool>, StatusCode> {
    Ok(Json(true))
}

pub async fn handle_quick_connect_initiate(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<QuickConnectSession>, StatusCode> {
    let secret = Uuid::new_v4().to_string();
    let code = generate_code();
    let (device_id, device_name, app_name, app_version) = parse_client_info(&headers);

    info!(
        "Initiating Quick Connect session for {} / {} ({})",
        app_name, device_name, device_id
    );

    let session = QuickConnectSession::new(
        secret.clone(),
        code,
        device_id,
        device_name,
        app_name,
        app_version,
    );

    let session = state.quick_connect.store_session(session);
    state.quick_connect.cleanup_expired();

    Ok(Json(session))
}

pub async fn handle_quick_connect_authorize(
    Query(params): Query<AuthorizeQuery>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<bool>, StatusCode> {
    let user_id = resolve_authorize_user_id(&state, &headers, params.user_id).await?;

    let success = state
        .quick_connect
        .update_session_by_code(&params.code, |session| {
            session.authenticated = true;
            session.user_id = Some(user_id.clone());
        });

    if success {
        info!(
            "Authorized Quick Connect code {} for user {}",
            params.code, user_id
        );
        Ok(Json(true))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

/// Resolve the user approving a Quick Connect code, from the caller's token.
///
/// The user id is always taken from the authenticated virtual token, never
/// from the request: a caller-supplied `userId` used to be trusted verbatim,
/// which let anyone approve their own code on behalf of any user id and then
/// collect that user's token. A `userId` may still be sent (clients echo the
/// one they logged in with) but only to be checked against the token's user;
/// a mismatch is rejected. The canonical id from the token is returned so it,
/// not a client-formatted value, is stored on the session.
async fn resolve_authorize_user_id(
    state: &AppState,
    headers: &HeaderMap,
    user_id: Option<String>,
) -> Result<String, StatusCode> {
    let token = extract_virtual_token(headers).ok_or_else(|| {
        warn!("Quick Connect authorize called without a virtual token");
        StatusCode::UNAUTHORIZED
    })?;

    let user = state
        .user_authorization
        .get_user_by_virtual_key(&token)
        .await
        .map_err(|e| {
            warn!("Failed to resolve user from virtual token: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if let Some(requested) = user_id {
        if !user_ids_match(&requested, &user.id) {
            warn!("Quick Connect authorize userId does not match the authenticated user");
            return Err(StatusCode::FORBIDDEN);
        }
    }

    Ok(user.id)
}

/// Compare two Jellyfin user ids. Ids are 32-hex-char UUIDs but clients may
/// send them hyphenated, so parse both as UUIDs when possible and fall back to
/// a case-insensitive string compare.
fn user_ids_match(a: &str, b: &str) -> bool {
    match (Uuid::parse_str(a), Uuid::parse_str(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a.eq_ignore_ascii_case(b),
    }
}

fn extract_virtual_token(headers: &HeaderMap) -> Option<String> {
    if let Some(header) = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
    {
        if let Ok(auth) = Authorization::parse(header) {
            if let Some(token) = auth.token {
                return Some(token);
            }
        }
    }

    if let Some(header) = headers
        .get("x-emby-authorization")
        .and_then(|value| value.to_str().ok())
    {
        if let Ok(auth) = Authorization::parse_with_legacy(header, true) {
            if let Some(token) = auth.token {
                return Some(token);
            }
        }
    }

    if let Some(token) = headers
        .get("x-emby-token")
        .and_then(|value| value.to_str().ok())
    {
        return Some(token.to_string());
    }

    if let Some(token) = headers
        .get("x-mediabrowser-token")
        .and_then(|value| value.to_str().ok())
    {
        return Some(token.to_string());
    }

    None
}

pub async fn handle_quick_connect_connect(
    Query(params): Query<ConnectQuery>,
    State(state): State<AppState>,
) -> Result<Json<QuickConnectSession>, StatusCode> {
    if let Some(session) = state.quick_connect.get_session(&params.secret) {
        Ok(Json(session))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

pub async fn handle_authenticate_with_quick_connect(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<QuickConnectAuthenticateRequest>,
) -> Result<crate::sessions::AuthenticationResponse, StatusCode> {
    let session = state
        .quick_connect
        .get_session(&request.secret)
        .ok_or(StatusCode::NOT_FOUND)?;

    let Some(user_id) = session.user_id.clone() else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    if !session.authenticated {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let user = state
        .user_authorization
        .get_user_by_id(&user_id)
        .await
        .map_err(|e| {
            warn!("Database error while fetching user {}: {}", user_id, e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let mut servers = state
        .server_storage
        .list_servers()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if servers.is_empty() {
        return Err(StatusCode::NOT_FOUND);
    }

    let server_mappings = state
        .user_authorization
        .list_server_mappings(&user.id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if server_mappings.is_empty() {
        warn!(
            "Quick Connect user '{}' has no server mappings",
            user.original_username
        );
        return Err(StatusCode::UNAUTHORIZED);
    }

    let mut auth_tasks = Vec::with_capacity(server_mappings.len());

    let authorization = effective_quick_connect_authorization(&headers, &session, &user.id);

    for server_mapping in server_mappings {
        if let Some(pos) = servers
            .iter()
            .position(|s| s.id == server_mapping.server_id)
        {
            let server = servers.remove(pos);
            let state = state.clone();
            let authorization = authorization.clone();
            let user = user.clone();

            auth_tasks.push(tokio::spawn(async move {
                authenticate_with_mapping_on_server(
                    state,
                    authorization,
                    user,
                    server,
                    server_mapping,
                )
                .await
            }));
        } else {
            debug!(
                "Skipping mapping for unknown server ID {}",
                server_mapping.server_id
            );
        }
    }

    let mut successful_auths = Vec::new();

    for task in auth_tasks {
        match task.await {
            Ok(Ok(auth_response)) => successful_auths.push(auth_response),
            Ok(Err(QuickConnectAuthError::Network(e))) => {
                debug!("Quick Connect auth request failed: {}", e)
            }
            Ok(Err(QuickConnectAuthError::Parse(e))) => {
                debug!("Quick Connect auth parse failed: {}", e)
            }
            Ok(Err(QuickConnectAuthError::Internal(e))) => {
                debug!("Quick Connect internal auth error: {}", e)
            }
            Ok(Err(QuickConnectAuthError::InvalidCredentials)) => {
                debug!("Quick Connect auth rejected by upstream server")
            }
            Err(e) => warn!("Quick Connect auth task failed: {}", e),
        }
    }

    state.quick_connect.remove_session(&request.secret);

    if successful_auths.is_empty() {
        Err(StatusCode::UNAUTHORIZED)
    } else {
        Ok(crate::sessions::authentication_response(
            successful_auths[0].clone(),
        ))
    }
}

#[derive(Debug)]
enum QuickConnectAuthError {
    Network(String),
    InvalidCredentials,
    Parse(String),
    Internal(String),
}

async fn authenticate_with_mapping_on_server(
    state: AppState,
    authorization: Authorization,
    user: crate::user_authorization_service::User,
    server: crate::server_storage::Server,
    server_mapping: crate::user_authorization_service::ServerMapping,
) -> Result<AuthenticateResponse, QuickConnectAuthError> {
    let admin_password = state.get_admin_password().await;
    let admin_password_hash: HashedPassword = (&admin_password).into();
    let user_mapping_key = user.local_credential.mapping_key();

    let mapped_password = state.user_authorization.decrypt_server_mapping_password(
        &server_mapping,
        &user_mapping_key,
        &admin_password_hash,
        None,
        Some(&admin_password),
    );

    let client_info = ClientInfo {
        client: authorization.client.clone(),
        device: authorization.device.clone(),
        device_id: authorization.device_id.clone(),
        version: authorization.version.clone(),
    };

    let jellyfin_client = JellyfinClient::new_with_client(
        server.url.as_str(),
        client_info,
        state.reqwest_client.clone(),
    )
    .map_err(|e| QuickConnectAuthError::Internal(e.to_string()))?;

    let mut auth_response: AuthenticateResponse = jellyfin_client
        .authenticate_by_name_typed(
            server_mapping.mapped_username.as_str(),
            mapped_password.as_str(),
        )
        .await
        .map_err(map_jellyfin_auth_error)?;

    state
        .user_authorization
        .add_server_mapping(
            &user.id,
            &server,
            &server_mapping.mapped_username,
            &mapped_password,
            Some(&user_mapping_key),
        )
        .await
        .map_err(|e| QuickConnectAuthError::Internal(e.to_string()))?;

    let auth_token = auth_response.access_token.clone();
    let original_user_id = auth_response.user.id.clone();

    let server_id = state.config.read().await.server_id.clone();
    auth_response.server_id = server_id.clone();
    auth_response.user.server_id = server_id.clone();
    auth_response.session_info.server_id = server_id;

    auth_response.session_info.user_id = user.id.clone();
    auth_response.user.name = user.original_username.clone();
    auth_response.session_info.user_name = user.original_username.clone();
    auth_response.user.policy.is_administrator = false;
    auth_response.user.policy.sync_play_access = SyncPlayUserAccessType::CreateAndJoinGroups;
    auth_response.access_token = user.virtual_key.clone();
    auth_response.user.id = user.id.clone();

    crate::sessions::decorate_authentication(&state, &user, &authorization, &mut auth_response)
        .await;
    let mut auth_to_store = authorization;
    auth_to_store.token = Some(auth_token.clone());

    state
        .user_authorization
        .store_authorization_session(
            &user.id,
            &server,
            &auth_to_store,
            auth_token,
            original_user_id,
            None,
        )
        .await
        .map_err(|e| QuickConnectAuthError::Internal(e.to_string()))?;

    info!(
        "Quick Connect authenticated '{}' on server '{}'",
        user.original_username, server.name
    );

    Ok(auth_response)
}

fn map_jellyfin_auth_error(err: JellyfinApiError) -> QuickConnectAuthError {
    match err {
        JellyfinApiError::AuthenticationFailed(_) => QuickConnectAuthError::InvalidCredentials,
        JellyfinApiError::Unauthorized | JellyfinApiError::Forbidden => {
            QuickConnectAuthError::InvalidCredentials
        }
        JellyfinApiError::Serialization(e) => QuickConnectAuthError::Parse(e.to_string()),
        JellyfinApiError::InvalidResponse(e) => QuickConnectAuthError::Parse(e),
        JellyfinApiError::Network(e) => QuickConnectAuthError::Network(e.to_string()),
        JellyfinApiError::ServerError(e) => QuickConnectAuthError::Network(e),
        JellyfinApiError::UrlParse(e) => QuickConnectAuthError::Internal(e.to_string()),
        JellyfinApiError::NotFound => QuickConnectAuthError::Internal(
            "Users/AuthenticateByName endpoint was not found on target server".to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{AppConfig, MediaStreamingMode, MIGRATOR},
        media_storage_service::MediaStorageService,
        models::{AuthenticateResponse, SessionInfo, SyncPlayUserAccessType, User, UserPolicy},
        server_storage::ServerStorageService,
        session_storage::SessionStorage,
        user_authorization_service::{Device, UserAuthorizationService},
        AppState, DataContext, ProxyProcessors,
    };
    use axum::{extract::Query, Json};
    use hyper::http::HeaderValue;
    use sqlx::SqlitePool;
    use std::{collections::HashMap, sync::Arc};
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    async fn create_test_app_state() -> AppState {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        MIGRATOR.run(&pool).await.unwrap();
        let server_storage = ServerStorageService::new(pool.clone());
        let media_storage = MediaStorageService::new(pool.clone());

        let data_context = DataContext {
            user_authorization: Arc::new(UserAuthorizationService::new(pool.clone())),
            server_storage: Arc::new(server_storage.clone()),
            media_storage: Arc::new(media_storage.clone()),
            virtual_library_service: Arc::new(
                crate::virtual_library_service::VirtualLibraryService::new(
                    pool,
                    server_storage,
                    media_storage,
                ),
            ),
            play_sessions: Arc::new(SessionStorage::new()),
            config: Arc::new(tokio::sync::RwLock::new(AppConfig::default())),
        };

        let processors = ProxyProcessors::new(data_context.clone());

        AppState::new(
            reqwest::Client::new(),
            reqwest::Client::new(),
            data_context,
            processors,
            QuickConnectStorage::new(),
        )
    }

    #[test]
    fn quick_connect_session_serializes_to_jellyfin_shape() {
        let session = QuickConnectSession::new(
            "secret-1".to_string(),
            "123456".to_string(),
            "device-1".to_string(),
            "Test Device".to_string(),
            "Test App".to_string(),
            "1.2.3".to_string(),
        );

        let value = serde_json::to_value(session).unwrap();
        let obj = value.as_object().unwrap();

        assert!(obj.contains_key("Authenticated"));
        assert!(obj.contains_key("Secret"));
        assert!(obj.contains_key("Code"));
        assert!(obj.contains_key("DeviceId"));
        assert!(obj.contains_key("DeviceName"));
        assert!(obj.contains_key("AppName"));
        assert!(obj.contains_key("AppVersion"));
        assert!(obj.contains_key("DateAdded"));

        assert!(!obj.contains_key("UserId"));
        assert!(!obj.contains_key("ExpiresAt"));
    }

    #[test]
    fn quick_connect_dto_accepts_pascal_and_camel_secret() {
        let pascal: QuickConnectAuthenticateRequest =
            serde_json::from_str(r#"{"Secret":"abc"}"#).unwrap();
        let camel: QuickConnectAuthenticateRequest =
            serde_json::from_str(r#"{"secret":"xyz"}"#).unwrap();

        assert_eq!(pascal.secret, "abc");
        assert_eq!(camel.secret, "xyz");
    }

    #[test]
    fn authorize_query_accepts_pascal_and_camel_user_id() {
        let camel: AuthorizeQuery =
            serde_json::from_str(r#"{"code":"123456","userId":"user-1"}"#).unwrap();
        let pascal: AuthorizeQuery =
            serde_json::from_str(r#"{"Code":"123456","UserId":"user-2"}"#).unwrap();
        let missing: AuthorizeQuery = serde_json::from_str(r#"{"code":"123456"}"#).unwrap();

        assert_eq!(camel.code, "123456");
        assert_eq!(camel.user_id.as_deref(), Some("user-1"));
        assert_eq!(pascal.user_id.as_deref(), Some("user-2"));
        assert!(missing.user_id.is_none());
    }

    #[test]
    fn extract_virtual_token_supports_auth_and_token_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static(
                "MediaBrowser Client=\"Jellyfin Web\", Device=\"Firefox\", DeviceId=\"abc\", Version=\"10.10.7\", Token=\"token-1\"",
            ),
        );
        assert_eq!(extract_virtual_token(&headers).as_deref(), Some("token-1"));

        let mut x_emby_token = HeaderMap::new();
        x_emby_token.insert("x-emby-token", HeaderValue::from_static("token-2"));
        assert_eq!(
            extract_virtual_token(&x_emby_token).as_deref(),
            Some("token-2")
        );

        let mut media_browser_token = HeaderMap::new();
        media_browser_token.insert("x-mediabrowser-token", HeaderValue::from_static("token-3"));
        assert_eq!(
            extract_virtual_token(&media_browser_token).as_deref(),
            Some("token-3")
        );
    }

    #[test]
    fn detects_android_tv_clients() {
        assert!(is_android_tv_client("Jellyfin Android TV"));
        assert!(is_android_tv_client("Jellyfin Android TV (debug)"));
        assert!(!is_android_tv_client("Jellyfin Android"));
        assert!(!is_android_tv_client("Jellyfin Web"));
    }

    #[test]
    fn derives_android_tv_device_id_from_uuid_user_id() {
        let base_device_id = "androidtv-device-123";
        let simple_user_id = "550e8400e29b41d4a716446655440000";
        let derived = derive_android_tv_user_device_id(base_device_id, simple_user_id);

        assert_eq!(derived, "7094964e96c0e66e00671463e263fbdffce6b001");
    }

    #[test]
    fn quick_connect_uses_android_tv_user_scoped_device_id() {
        let session = QuickConnectSession::new(
            "secret-1".to_string(),
            "123456".to_string(),
            "session-device".to_string(),
            "Android TV".to_string(),
            "Jellyfin Android TV".to_string(),
            "1.0.0".to_string(),
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static(
                "MediaBrowser Client=\"Jellyfin Android TV\", Device=\"Chromecast\", DeviceId=\"androidtv-device-123\", Version=\"0.18.0\"",
            ),
        );

        let auth = effective_quick_connect_authorization(
            &headers,
            &session,
            "550e8400e29b41d4a716446655440000",
        );

        assert_eq!(auth.client, "Jellyfin Android TV");
        assert_eq!(auth.device, "Chromecast");
        assert_eq!(auth.version, "0.18.0");
        assert_eq!(auth.device_id, "7094964e96c0e66e00671463e263fbdffce6b001");
        assert!(auth.token.is_none());
    }

    #[test]
    fn quick_connect_falls_back_to_session_metadata_without_headers() {
        let session = QuickConnectSession::new(
            "secret-1".to_string(),
            "123456".to_string(),
            "session-device".to_string(),
            "Fallback Device".to_string(),
            "Unknown App".to_string(),
            "1.0.0".to_string(),
        );

        let headers = HeaderMap::new();
        let auth = effective_quick_connect_authorization(&headers, &session, "user-id");

        assert_eq!(auth.device_id, "session-device");
        assert_eq!(auth.device, "Fallback Device");
        assert_eq!(auth.client, "Unknown App");
    }

    #[tokio::test]
    async fn quick_connect_authentication_preserves_existing_web_session() {
        let state = create_test_app_state().await;
        let upstream = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/Users/AuthenticateByName"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(AuthenticateResponse {
                    user: User {
                        name: "mappeduser".to_string(),
                        server_id: "upstream-server".to_string(),
                        id: "upstream-user-id".to_string(),
                        policy: UserPolicy {
                            is_administrator: false,
                            sync_play_access: SyncPlayUserAccessType::None,
                            extra: HashMap::new(),
                        },
                        extra: HashMap::new(),
                    },
                    session_info: SessionInfo {
                        user_id: "upstream-user-id".to_string(),
                        user_name: "mappeduser".to_string(),
                        server_id: "upstream-server".to_string(),
                        extra: HashMap::new(),
                    },
                    access_token: "tv-upstream-token".to_string(),
                    server_id: "upstream-server".to_string(),
                }),
            )
            .mount(&upstream)
            .await;

        let upstream_server_id = state
            .server_storage
            .add_server("Upstream", &upstream.uri(), 100, MediaStreamingMode::Proxy)
            .await
            .unwrap();
        let upstream_server = state
            .server_storage
            .get_server_by_id(upstream_server_id)
            .await
            .unwrap()
            .unwrap();

        let user = state
            .user_authorization
            .get_or_create_user("MyUser", &"local-pass".into())
            .await
            .unwrap();

        state
            .user_authorization
            .add_server_mapping(
                &user.id,
                &upstream_server,
                "mappeduser",
                &"mappedpass".into(),
                None,
            )
            .await
            .unwrap();

        let existing_web_auth = Authorization {
            client: "Jellyfin Web".to_string(),
            device: "Firefox".to_string(),
            device_id: "web-device-id".to_string(),
            version: "10.10.7".to_string(),
            token: None,
        };

        state
            .user_authorization
            .store_authorization_session(
                &user.id,
                &upstream_server,
                &existing_web_auth,
                "web-upstream-token".to_string(),
                "upstream-user-id".to_string(),
                None,
            )
            .await
            .unwrap();

        let quick_connect_session = QuickConnectSession::new(
            "secret-1".to_string(),
            "123456".to_string(),
            "androidtv-base-device-id".to_string(),
            "Chromecast".to_string(),
            "Jellyfin Android TV".to_string(),
            "0.19.7".to_string(),
        );
        state.quick_connect.store_session(quick_connect_session);

        let mut browser_headers = HeaderMap::new();
        browser_headers.insert(
            "authorization",
            HeaderValue::from_str(&format!(
                "MediaBrowser Client=\"Jellyfin Web\", Device=\"Firefox\", DeviceId=\"web-device-id\", Version=\"10.10.7\", Token=\"{}\"",
                user.virtual_key
            ))
            .unwrap(),
        );

        let authorize_result = handle_quick_connect_authorize(
            Query(AuthorizeQuery {
                code: "123456".to_string(),
                user_id: None,
            }),
            axum::extract::State(state.clone()),
            browser_headers,
        )
        .await;
        assert!(authorize_result.is_ok());

        let mut tv_headers = HeaderMap::new();
        tv_headers.insert(
            "authorization",
            HeaderValue::from_static(
                "MediaBrowser Client=\"Jellyfin Android TV\", Device=\"Chromecast\", DeviceId=\"androidtv-base-device-id\", Version=\"0.19.7\"",
            ),
        );

        let auth_response = handle_authenticate_with_quick_connect(
            axum::extract::State(state.clone()),
            tv_headers,
            Json(QuickConnectAuthenticateRequest {
                secret: "secret-1".to_string(),
            }),
        )
        .await
        .unwrap()
        .1
         .0;

        assert_eq!(auth_response.access_token, user.virtual_key);

        let all_sessions = state
            .user_authorization
            .get_user_sessions(&user.id, None)
            .await
            .unwrap();
        assert_eq!(all_sessions.len(), 2, "web and TV sessions should coexist");

        let web_sessions = state
            .user_authorization
            .get_user_sessions(
                &user.id,
                Some(Device {
                    client: "Jellyfin Web".to_string(),
                    device: "Firefox".to_string(),
                    device_id: "web-device-id".to_string(),
                    version: "10.10.7".to_string(),
                }),
            )
            .await
            .unwrap();

        assert_eq!(
            web_sessions.len(),
            1,
            "existing web session should remain available"
        );
        assert_eq!(web_sessions[0].0.jellyfin_token, "web-upstream-token");
    }

    fn test_session(secret: &str, code: &str) -> QuickConnectSession {
        QuickConnectSession::new(
            secret.to_string(),
            code.to_string(),
            "device-id".to_string(),
            "Device".to_string(),
            "App".to_string(),
            "1.0.0".to_string(),
        )
    }

    fn authorization_header(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_str(&format!(
                "MediaBrowser Client=\"App\", Device=\"Device\", DeviceId=\"device-id\", Version=\"1.0.0\", Token=\"{token}\""
            ))
            .unwrap(),
        );
        headers
    }

    #[test]
    fn get_session_rejects_the_code_used_as_a_secret() {
        let storage = QuickConnectStorage::new();
        let stored = storage.store_session(test_session(
            "11111111-1111-4111-8111-111111111111",
            "123456",
        ));

        // The code must never unlock a session in the secret's place.
        assert!(storage.get_session(&stored.code).is_none());
        assert!(storage.get_session(&stored.secret).is_some());
    }

    #[test]
    fn update_by_code_rejects_the_secret_used_as_a_code() {
        let storage = QuickConnectStorage::new();
        let stored = storage.store_session(test_session(
            "22222222-2222-4222-8222-222222222222",
            "234567",
        ));

        assert!(!storage.update_session_by_code(&stored.secret, |s| s.authenticated = true));
        assert!(storage.update_session_by_code(&stored.code, |s| s.authenticated = true));
    }

    #[test]
    fn remove_session_ignores_a_code() {
        let storage = QuickConnectStorage::new();
        let stored = storage.store_session(test_session(
            "33333333-3333-4333-8333-333333333333",
            "345678",
        ));

        assert!(storage.remove_session(&stored.code).is_none());
        assert!(storage.get_session(&stored.secret).is_some());
        assert!(storage.remove_session(&stored.secret).is_some());
    }

    #[test]
    fn store_session_regenerates_a_colliding_code() {
        let storage = QuickConnectStorage::new();
        let first = storage.store_session(test_session(
            "44444444-4444-4444-8444-444444444444",
            "456789",
        ));
        assert_eq!(first.code, "456789");

        // A second session initiated with the same code must not steal it.
        let second = storage.store_session(test_session(
            "55555555-5555-4555-8555-555555555555",
            "456789",
        ));
        assert_ne!(second.code, "456789");
        assert_eq!(
            storage.get_session(&first.secret).unwrap().code,
            "456789",
            "the first session keeps its code"
        );
        assert_eq!(
            storage.get_session(&second.secret).unwrap().code,
            second.code
        );
    }

    #[tokio::test]
    async fn authorize_requires_a_token_even_with_a_user_id() {
        let state = create_test_app_state().await;
        let stored = state.quick_connect.store_session(test_session(
            "66666666-6666-4666-8666-666666666666",
            "567890",
        ));

        let result = handle_quick_connect_authorize(
            Query(AuthorizeQuery {
                code: stored.code.clone(),
                user_id: Some("deadbeefdeadbeefdeadbeefdeadbeef".to_string()),
            }),
            axum::extract::State(state.clone()),
            HeaderMap::new(),
        )
        .await;

        assert_eq!(result.unwrap_err(), StatusCode::UNAUTHORIZED);
        assert!(
            !state
                .quick_connect
                .get_session(&stored.secret)
                .unwrap()
                .authenticated
        );
    }

    #[tokio::test]
    async fn authorize_rejects_a_foreign_user_id() {
        let state = create_test_app_state().await;
        let user = state
            .user_authorization
            .get_or_create_user("owner", &"pass".into())
            .await
            .unwrap();
        let stored = state.quick_connect.store_session(test_session(
            "77777777-7777-4777-8777-777777777777",
            "678901",
        ));

        let result = handle_quick_connect_authorize(
            Query(AuthorizeQuery {
                code: stored.code.clone(),
                user_id: Some(Uuid::new_v4().simple().to_string()),
            }),
            axum::extract::State(state.clone()),
            authorization_header(&user.virtual_key),
        )
        .await;

        assert_eq!(result.unwrap_err(), StatusCode::FORBIDDEN);
        let session = state.quick_connect.get_session(&stored.secret).unwrap();
        assert!(!session.authenticated);
        assert!(session.user_id.is_none());
    }

    #[tokio::test]
    async fn authorize_accepts_a_hyphenated_user_id_and_stores_the_canonical_id() {
        let state = create_test_app_state().await;
        let user = state
            .user_authorization
            .get_or_create_user("owner", &"pass".into())
            .await
            .unwrap();
        let hyphenated = Uuid::parse_str(&user.id).unwrap().hyphenated().to_string();
        let stored = state.quick_connect.store_session(test_session(
            "88888888-8888-4888-8888-888888888888",
            "789012",
        ));

        let result = handle_quick_connect_authorize(
            Query(AuthorizeQuery {
                code: stored.code.clone(),
                user_id: Some(hyphenated),
            }),
            axum::extract::State(state.clone()),
            authorization_header(&user.virtual_key),
        )
        .await;

        assert!(result.is_ok());
        let session = state.quick_connect.get_session(&stored.secret).unwrap();
        assert!(session.authenticated);
        assert_eq!(
            session.user_id.as_deref(),
            Some(user.id.as_str()),
            "the canonical id from the token is stored, not the client's format"
        );
    }

    #[test]
    fn user_ids_match_across_formats() {
        let simple = "deadbeefdeadbeefdeadbeefdeadbeef";
        let hyphenated = "DEADBEEF-DEAD-BEEF-DEAD-BEEFDEADBEEF";
        assert!(user_ids_match(simple, hyphenated));
        assert!(user_ids_match(simple, simple));
        assert!(!user_ids_match(simple, "feedfacefeedfacefeedfacefeedface"));
    }
}
