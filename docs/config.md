# Jellyswarrm Configuration Documentation  

Jellyswarrm stores its configuration in a **TOML** file located at:  
`./data/jellyswarrm.toml` (inside the container).  

The SQLite database is stored at:  
`./data/jellyswarrm.db`.  

To persist your configuration and database across container restarts, mount a volume to the `./data` directory.  

You can override the default configuration in two ways:  
1. Provide your own `jellyswarrm.toml` file and mount it into the container.  
2. Use environment variables to override individual settings.  

---

## Configuration Options  

The table below lists all available configuration options:  

| Variable | Default Value | Environment Key | Description |
|----------|---------------|-----------------|-------------|
| `server_id` | *Generated UUID (32 hex chars)* | `JELLYSWARRM_SERVER_ID` | Unique identifier for the proxy server instance. |
| `public_address` | `localhost:3000` | `JELLYSWARRM_PUBLIC_ADDRESS` | Public address where the proxy is accessible. |
| `server_name` | `Jellyswarrm Proxy` | `JELLYSWARRM_SERVER_NAME` | Display name for the proxy server. |
| `host` | `0.0.0.0` | `JELLYSWARRM_HOST` | Host address the server binds to. |
| `port` | `3000` | `JELLYSWARRM_PORT` | Port number for the proxy server. |
| `include_server_name_in_media` | `true` | `JELLYSWARRM_INCLUDE_SERVER_NAME_IN_MEDIA` | Append the server name to media titles in responses. |
| `username` | `admin` | `JELLYSWARRM_USERNAME` | Default admin username. |
| `password` | `jellyswarrm` | `JELLYSWARRM_PASSWORD` | Default admin password (⚠️ change this in production). |
| `session_key` | *Generated 64-byte key* | `JELLYSWARRM_SESSION_KEY` | Base64-encoded session encryption key. |
| `timeout` | `20` | `JELLYSWARRM_TIMEOUT` | Request timeout in seconds. |
| `preconfigured_servers` | `[]` | `JELLYSWARRM_PRECONFIGURED_SERVERS` | Optional list of preconfigured Jellyfin servers (`url`, `name`, `priority`, `media_streaming_mode`). |
| `ui_route` | `ui` | `JELLYSWARRM_UI_ROUTE` | URL path segment for accessing the web UI (e.g., `/ui`). |
| `url_prefix` | *(none)* | `JELLYSWARRM_URL_PREFIX` | Optional URL prefix for all routes (useful for reverse proxy setups). |
| `server_background_check_interval_secs` | `30` | `JELLYSWARRM_SERVER_BACKGROUND_CHECK_INTERVAL_SECS` | Interval in seconds for background server health checks. |
| `auto_create_users_on_login` | `true` | `JELLYSWARRM_AUTO_CREATE_USERS_ON_LOGIN` | Automatically create local users on successful upstream login. |
| `merge_libraries` | `true` | `JELLYSWARRM_MERGE_LIBRARIES` | Merge libraries with matching names across servers into virtual libraries. |
| `deduplicate_media` | `false` | `JELLYSWARRM_DEDUPLICATE_MEDIA` | Collapse the same movie or show (series/season/episode) on multiple servers into one item whose versions are served by the different hosts (Jellyfin-style linked versions; Jellyfin v12 adds multi-versions for episodes). Legacy key `deduplicate_movies` / env `JELLYSWARRM_DEDUPLICATE_MOVIES` still loads. |

---

### Notes
- The `session_key` is generated as a secure 64-byte key if not specified, and is stored in the config file for reuse.  
- Each server now has its own streaming mode (`Redirect` or `Proxy`). For preconfigured servers, omit `media_streaming_mode` to use the default `Redirect`.
- Configuration files are resolved from the data directory (`./data` by default), which can be overridden with `JELLYSWARRM_DATA_DIR`.

---

## Single sign-on (OpenID Connect)

The web UI can additionally log in through an OpenID Connect provider (authorization code flow with PKCE). Add an `[oidc]` section to `jellyswarrm.toml`:

```toml
[oidc]
issuer_url = "https://auth.example.com"
client_id = "jellyswarrm"
client_secret = "..."            # omit for a public client
redirect_url = "https://jellyswarrm.example.com/ui/oidc/callback"
admin_group = "jellyswarrm-admins" # optional
user_group = "jellyfin"            # optional: create accounts on first sign-in
```

- Register `redirect_url` exactly as written at the provider; it is not derived from the request, so a TLS-terminating proxy cannot change its scheme. The path is `/<ui_route>/oidc/callback` (with `url_prefix` in front if one is set).
- The scopes `openid groups` are requested. The login page offers **Sign in with SSO**, which enters the Jellyswarrm account the user has **linked**, and, when `admin_group` is set, **Sign in with SSO as admin**, which requires membership in that group (from the `groups` claim). Someone who is both picks per login. To link an account: sign in once with the account's password, open **Profile → Link single sign-on** and complete the provider login. The link stores the provider's issuer and subject, never a username, so renaming an account at the provider cannot redirect a login to someone else's account. No accounts are created; users get their Jellyswarrm account as before, by logging in once from a Jellyfin client.
- With `user_group` set, a member of that group who has no Jellyswarrm account yet gets one on their first **Sign in with SSO**: named after `preferred_username`, linked to their identity, and without any password - it can only be entered through single sign-on. If that name is already taken, the login is refused rather than attached to the existing account.
- Such an account connects its servers without passwords too: under **Servers**, **Quick Connect** shows a code from that server, which the user approves in that server's own web UI (Jellyfin's Quick Connect page, reachable however that server lets them sign in). Jellyswarrm keeps the resulting upstream access token (encrypted with a key derived from `session_key`; changing `session_key` means reconnecting) instead of a password, and signs each device in upstream through the same Quick Connect mechanism. The upstream server must have Quick Connect enabled. To revoke, remove the "Jellyswarrm (<user>)" device in that server's dashboard.
- The web player's login page shows **Sign in with SSO** too (instead of the list of upstream servers). It runs the same single sign-on and then signs that browser's player in directly, using the user's connected servers - no password and no Quick Connect code.
- Native Jellyfin apps cannot follow a browser login. They sign in with Quick Connect instead: pick "Quick Connect" in the app, then enter the code under **Quick Connect** in the web UI after signing in there. The device is logged in with the servers connected to that account. The admin account has no media access and cannot approve codes.
