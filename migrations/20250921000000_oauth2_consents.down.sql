ALTER TABLE auth_oauth2_client_authorization_codes
    RENAME COLUMN scope TO scopes;

ALTER TABLE auth_oauth2_client_authorization_codes
    RENAME CONSTRAINT auth_oauth2_client_authorization_codes_scope_check
    TO auth_oauth2_client_authorization_codes_scopes_check;

ALTER TABLE auth_oauth2_client_access_tokens
    RENAME COLUMN scope TO scopes;

ALTER TABLE auth_oauth2_client_access_tokens
    RENAME CONSTRAINT auth_oauth2_client_access_tokens_scope_check
    TO auth_oauth2_client_access_tokens_scopes_check;

ALTER TABLE auth_oauth2_client_refresh_tokens
    RENAME COLUMN scope TO scopes;

ALTER TABLE auth_oauth2_client_refresh_tokens
    RENAME CONSTRAINT auth_oauth2_client_refresh_tokens_scope_check
    TO auth_oauth2_client_refresh_tokens_scopes_check;

DROP TABLE IF EXISTS auth_oauth2_client_consents;
