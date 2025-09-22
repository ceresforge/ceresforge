ALTER TABLE auth_oauth2_client_authorization_codes
    RENAME COLUMN scopes TO scope;

ALTER TABLE auth_oauth2_client_authorization_codes
    RENAME CONSTRAINT auth_oauth2_client_authorization_codes_scopes_check
    TO auth_oauth2_client_authorization_codes_scope_check;

ALTER TABLE auth_oauth2_client_access_tokens
    RENAME COLUMN scopes TO scope;

ALTER TABLE auth_oauth2_client_access_tokens
    RENAME CONSTRAINT auth_oauth2_client_access_tokens_scopes_check
    TO auth_oauth2_client_access_tokens_scope_check;

ALTER TABLE auth_oauth2_client_refresh_tokens
    RENAME COLUMN scopes TO scope;

ALTER TABLE auth_oauth2_client_refresh_tokens
    RENAME CONSTRAINT auth_oauth2_client_refresh_tokens_scopes_check
    TO auth_oauth2_client_refresh_tokens_scope_check;

CREATE TABLE IF NOT EXISTS auth_oauth2_client_consents (
    id bigint
        PRIMARY KEY
        GENERATED ALWAYS AS IDENTITY,
    user_id bigint
        NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,
    client_id text
        NOT NULL
        REFERENCES auth_oauth2_clients(id) ON DELETE CASCADE,
    scope text
        NOT NULL
        CONSTRAINT auth_oauth2_client_consents_scope_check
        CHECK (
            char_length(scope) < 512
        ),
    created_at timestamp with time zone
        NOT NULL
        DEFAULT now(),
    updated_at timestamp with time zone
        NOT NULL
        DEFAULT now(),

    CONSTRAINT auth_oauth2_client_consents_user_id_client_id_key
    UNIQUE (user_id, client_id)
);

CREATE INDEX IF NOT EXISTS auth_oauth2_client_consents_client_id_key
    ON auth_oauth2_client_consents
    USING btree (client_id);
