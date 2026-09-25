-- An upstream access token, as an alternative to a stored password: a
-- mapping connected through the upstream's Quick Connect keeps the token
-- (encrypted) and an empty mapped_password. Exactly one of the two is used.
ALTER TABLE server_mappings ADD COLUMN upstream_token TEXT;
