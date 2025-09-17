CREATE TABLE IF NOT EXISTS users (
    id bigint
        PRIMARY KEY
        GENERATED ALWAYS AS IDENTITY,
    username text
        NOT NULL
        UNIQUE
        CONSTRAINT users_username_check
        CHECK (
            char_length(username) >= 3
            AND char_length(username) < 32
            AND username ~ '^[a-z][a-z0-9_-]*$'
        ),
    email text
        UNIQUE
        CONSTRAINT users_email_check
        CHECK (
            email IS NULL
            OR (
                char_length(email) >= 3
                AND char_length(email) < 256
            )
        ),
    is_admin boolean
        NOT NULL
        DEFAULT false,
    first_name text
        CONSTRAINT users_first_name_check
        CHECK (
            first_name IS NULL
            OR (
                char_length(first_name) > 0
                AND char_length(first_name) < 64
            )
        ),
    last_name text
        CONSTRAINT users_last_name_check
        CHECK (
            last_name IS NULL
            OR (
                char_length(last_name) > 0
                AND char_length(last_name) < 64
            )
        ),
    created_at timestamp with time zone
        NOT NULL
        DEFAULT now(),
    updated_at timestamp with time zone
        NOT NULL
        DEFAULT now()
);

CREATE TABLE IF NOT EXISTS auth_cookies (
    id text
        PRIMARY KEY
        CONSTRAINT auth_cookies_id_check
        CHECK (
            char_length(id) = 43
            AND id ~ '^[A-Za-z0-9_-]+$'
        ),
    user_id bigint
        NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,
    created_at timestamp with time zone
        NOT NULL
        DEFAULT now(),
    expires_at timestamp with time zone
        NOT NULL
        DEFAULT (now() + interval '90 days')
);

CREATE INDEX IF NOT EXISTS auth_cookies_user_id_key
    ON auth_cookies USING btree (user_id);

CREATE TABLE IF NOT EXISTS auth_local_credentials (
    user_id bigint
        PRIMARY KEY
        REFERENCES users(id) ON DELETE CASCADE,
    password_hash text
        NOT NULL
        CONSTRAINT auth_local_credentials_password_hash_check
        CHECK (
            char_length(password_hash) > 0
            AND char_length(password_hash) < 128
        ),
    created_at timestamp with time zone
        NOT NULL
        DEFAULT now(),
    updated_at timestamp with time zone
        NOT NULL
        DEFAULT now()
);

CREATE TABLE IF NOT EXISTS auth_saml_providers (
    id bigint
        PRIMARY KEY
        GENERATED ALWAYS AS IDENTITY,
    slug text
        NOT NULL
        UNIQUE
        CONSTRAINT auth_saml_providers_slug_check
        CHECK (
            char_length(slug) >= 3
            AND char_length(slug) < 32
            AND slug ~ '^[a-z][a-z0-9-]*$'
        ),
    name text
        NOT NULL
        CONSTRAINT auth_saml_providers_name_check
        CHECK (
            char_length(name) >= 3
            AND char_length(name) < 32
        ),
    metadata_url text
        NOT NULL
        CONSTRAINT auth_saml_providers_metadata_url_check
        CHECK (
            char_length(metadata_url) > 0
            AND char_length(metadata_url) < 256
        ),
    sso_url text
        NOT NULL
        CONSTRAINT auth_saml_providers_sso_url_check
        CHECK (
            char_length(sso_url) > 0
            AND char_length(sso_url) < 256
        ),
    requested_attributes jsonb
        NOT NULL,
    mapped_attributes jsonb
        NOT NULL,
    is_user_creation_allowed boolean
        NOT NULL
        DEFAULT false,
    created_at timestamp with time zone
        NOT NULL
        DEFAULT now(),
    updated_at timestamp with time zone
        NOT NULL
        DEFAULT now()
);

CREATE TABLE IF NOT EXISTS auth_saml_provider_requests (
    id uuid
        PRIMARY KEY,
    user_id bigint
        REFERENCES users(id) ON DELETE CASCADE,
    provider_id bigint
        NOT NULL
        REFERENCES auth_saml_providers(id) ON DELETE CASCADE,
    redirect text
        CONSTRAINT auth_saml_provider_requests_redirect_check
        CHECK (redirect IS NULL OR char_length(redirect) > 0),
    created_at timestamp with time zone
        NOT NULL
        DEFAULT now(),
    expires_at timestamp with time zone
        NOT NULL
        DEFAULT (now() + interval '10 minutes'),
    completed_at timestamp with time zone,
    name_id text
        CONSTRAINT auth_saml_provider_requests_name_id_check
        CHECK (
            name_id IS NULL
            OR (
                char_length(name_id) > 0
                AND char_length(name_id) < 32
                AND name_id ~ '^[a-z][a-z0-9_-]*$'
            )
        ),
    attributes jsonb,

    CONSTRAINT auth_saml_provider_requests_check
    CHECK (
        (
            completed_at IS NULL
            AND name_id IS NULL
            AND attributes IS NULL
        )
        OR (
            completed_at IS NOT NULL
            AND name_id IS NOT NULL
            AND attributes IS NOT NULL
        )
    )
);

CREATE TABLE IF NOT EXISTS auth_saml_provider_credentials (
    id bigint
        GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id bigint
        NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,
    provider_id bigint
        NOT NULL
        REFERENCES auth_saml_providers(id) ON DELETE CASCADE,
    name_id text
        NOT NULL
        CONSTRAINT auth_saml_provider_credentials_name_id_check
        CHECK (
            char_length(name_id) > 0
            AND char_length(name_id) < 32
            AND name_id ~ '^[a-z][a-z0-9_-]*$'
        ),
    attributes jsonb NOT NULL,
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    updated_at timestamp with time zone NOT NULL DEFAULT now(),

    CONSTRAINT auth_saml_provider_credentials_provider_id_name_id_key
    UNIQUE (provider_id, name_id),

    CONSTRAINT auth_saml_provider_credentials_provider_id_user_id_key
    UNIQUE (provider_id, user_id)
);

CREATE TABLE IF NOT EXISTS auth_oauth2_clients (
    id text
        PRIMARY KEY
        CONSTRAINT auth_oauth2_clients_id_check
        CHECK (char_length(id) = 32 AND id ~ '^[A-Za-z0-9_-]+$'),
    secret_hash text
        NOT NULL
        CONSTRAINT auth_oauth2_clients_secret_hash_check
        CHECK (
            char_length(secret_hash) > 0
            AND char_length(secret_hash) < 128
        ),
    name text
        NOT NULL
        CONSTRAINT auth_oauth2_clients_name_check
        CHECK (
            char_length(name) >= 3
            AND char_length(name) < 32
        ),
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
        CHECK (
            char_length(uri) > 0
            AND char_length(uri) < 512
        ),
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
        CHECK (
            char_length(code) = 22
            AND code ~ '^[A-Za-z0-9_-]+$'
        ),
    client_id text
        NOT NULL
        REFERENCES auth_oauth2_clients(id) ON DELETE CASCADE,
    user_id bigint
        NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri text
        NOT NULL
        CONSTRAINT auth_oauth2_client_authorization_codes_redirect_uri_check
        CHECK (
            char_length(redirect_uri) > 0
            AND char_length(redirect_uri) < 512
        ),
    scopes text
        NOT NULL
        CONSTRAINT auth_oauth2_client_authorization_codes_scopes_check
        CHECK (
            char_length(scopes) < 512
        ),
    created_at timestamp with time zone
        NOT NULL
        DEFAULT now(),
    expires_at timestamp with time zone
        NOT NULL
        DEFAULT (now() + interval '10 minutes'),
    completed_at timestamp with time zone
);

CREATE TABLE IF NOT EXISTS auth_oauth2_client_access_tokens (
    id text
        PRIMARY KEY
        CONSTRAINT auth_oauth2_client_access_tokens_id_check
        CHECK (
            char_length(id) = 43
            AND id ~ '^[A-Za-z0-9_-]+$'
        ),
    client_id text
        NOT NULL
        REFERENCES auth_oauth2_clients(id) ON DELETE CASCADE,
    user_id bigint
        NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,
    scopes text
        NOT NULL
        CONSTRAINT auth_oauth2_client_access_tokens_scopes_check
        CHECK (
            char_length(scopes) < 512
        ),
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
        CHECK (
            char_length(scopes) < 512
        ),
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
