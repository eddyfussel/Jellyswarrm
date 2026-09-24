-- Links an OpenID Connect identity (issuer + subject) to a local user.
-- A link is created by the user while logged in, so SSO never trusts a
-- provider-side username to pick the local account.
CREATE TABLE oidc_identities (
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (issuer, subject),
    UNIQUE (user_id, issuer)
);
