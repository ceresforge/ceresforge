ALTER TABLE sessions
    DROP CONSTRAINT IF EXISTS sessions_id_check;

ALTER TABLE sessions
    ADD CONSTRAINT sessions_id_check
    CHECK (char_length(id) = 43 AND id ~ '^[A-Za-z0-9_-]+$');

CREATE TABLE IF NOT EXISTS auth_oauth2_clients (
    id text
        PRIMARY KEY
        CONSTRAINT auth_oauth2_clients_id_check
        CHECK (char_length(id) = 32 AND id ~ '^[A-Za-z0-9_-]+$'),
    secret_hash text
        NOT NULL
        CONSTRAINT auth_oauth2_clients_secret_hash_check
        CHECK (char_length(secret_hash) > 0),
    name text
        NOT NULL
        CONSTRAINT auth_oauth2_clients_name_check
        CHECK (char_length(name) >= 3),
    created_at timestamp with time zone
        NOT NULL
        DEFAULT now(),
    updated_at timestamp with time zone
        NOT NULL
        DEFAULT now()
);

CREATE TABLE IF NOT EXISTS auth_oauth2_client_redirect_uris (
    id bigint
        PRIMARY KEY
        GENERATED ALWAYS AS IDENTITY,
    client_id text
        NOT NULL
        REFERENCES auth_oauth2_clients(id) ON DELETE CASCADE,
    uri text
        NOT NULL
        CONSTRAINT auth_oauth2_client_redirect_uris_uri_check
        CHECK (char_length(uri) > 0 AND char_length(uri) < 512),
    created_at timestamp with time zone
        NOT NULL
        DEFAULT now(),

    CONSTRAINT auth_oauth2_client_redirect_uris_client_id_uri_key
    UNIQUE (client_id, uri)
);

CREATE TABLE IF NOT EXISTS auth_oauth2_client_authorization_codes (
    code text
        PRIMARY KEY
        CONSTRAINT auth_oauth2_client_authorization_codes_code_check
        CHECK (char_length(code) = 22 AND code ~ '^[A-Za-z0-9_-]+$'),
    client_id text
        NOT NULL
        REFERENCES auth_oauth2_clients(id) ON DELETE CASCADE,
    user_id bigint
        NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri text
        NOT NULL
        CONSTRAINT auth_oauth2_client_authorization_codes_redirect_uri_check
        CHECK (char_length(redirect_uri) > 0 AND char_length(redirect_uri) < 2048),
    scopes text
        NOT NULL
        CONSTRAINT auth_oauth2_client_authorization_codes_scopes_check
        CHECK (char_length(scopes) < 512),
    created_at timestamp with time zone
        NOT NULL
        DEFAULT now(),
    completed_at timestamp with time zone,
    expires_at timestamp with time zone
        NOT NULL
        DEFAULT (now() + interval '10 minutes')
);

CREATE TABLE IF NOT EXISTS auth_oauth2_client_access_tokens (
    id text
        PRIMARY KEY
        CONSTRAINT auth_oauth2_client_access_tokens_id_check
        CHECK (char_length(id) = 43 AND id ~ '^[A-Za-z0-9_-]+$'),
    user_id bigint
        NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,
    client_id text
        NOT NULL
        REFERENCES auth_oauth2_clients(id) ON DELETE CASCADE,
    scopes text
        NOT NULL
        CONSTRAINT auth_oauth2_client_access_tokens_scopes_check
        CHECK (char_length(scopes) < 512),
    created_at timestamp with time zone
        NOT NULL
        DEFAULT now(),
    expires_at timestamp with time zone
        NOT NULL
        DEFAULT (now() + interval '1 hour')
);

CREATE INDEX IF NOT EXISTS auth_oauth2_client_access_tokens_user_id_key
    ON auth_oauth2_client_access_tokens
    USING btree (user_id);

CREATE TABLE IF NOT EXISTS auth_oauth2_client_refresh_tokens (
    id text
        PRIMARY KEY
        CONSTRAINT auth_oauth2_client_refresh_tokens_id_check
        CHECK (char_length(id) = 43 AND id ~ '^[A-Za-z0-9_-]+$'),
    user_id bigint
        NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,
    client_id text
        NOT NULL
        REFERENCES auth_oauth2_clients(id) ON DELETE CASCADE,
    scopes text
        NOT NULL
        CONSTRAINT auth_oauth2_client_refresh_tokens_scopes_check
        CHECK (char_length(scopes) < 512),
    created_at timestamp with time zone
        NOT NULL
        DEFAULT now(),
    expires_at timestamp with time zone
        NOT NULL
        DEFAULT (now() + interval '90 days')
);

CREATE INDEX IF NOT EXISTS auth_oauth2_client_refresh_tokens_user_id_key
    ON auth_oauth2_client_refresh_tokens
    USING btree (user_id);
