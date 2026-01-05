CREATE OR REPLACE FUNCTION set_updated_at()
    RETURNS TRIGGER AS $$
    BEGIN
        NEW.updated_at = now();
        RETURN NEW;
    END;
    $$ LANGUAGE plpgsql;

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

CREATE TRIGGER users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION set_updated_at();

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

CREATE INDEX IF NOT EXISTS auth_cookies_user_id_idx
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
            AND char_length(password_hash) < 256
        ),
    created_at timestamp with time zone
        NOT NULL
        DEFAULT now(),
    updated_at timestamp with time zone
        NOT NULL
        DEFAULT now()
);

CREATE TRIGGER auth_local_credentials_updated_at
    BEFORE UPDATE ON auth_local_credentials
    FOR EACH ROW
    EXECUTE FUNCTION set_updated_at();

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
    allow_registration boolean
        NOT NULL
        DEFAULT false,
    created_at timestamp with time zone
        NOT NULL
        DEFAULT now(),
    updated_at timestamp with time zone
        NOT NULL
        DEFAULT now()
);

CREATE TRIGGER auth_saml_providers_updated_at
    BEFORE UPDATE ON auth_saml_providers
    FOR EACH ROW
    EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS auth_saml_provider_requests (
    id bigint
        PRIMARY KEY
        GENERATED ALWAYS AS IDENTITY,
    external_id uuid
        NOT NULL
        UNIQUE,
    user_id bigint
        REFERENCES users(id) ON DELETE CASCADE,
    provider_id bigint
        NOT NULL
        REFERENCES auth_saml_providers(id) ON DELETE CASCADE,
    next text
        CONSTRAINT auth_saml_provider_requests_next_check
        CHECK (next IS NULL OR char_length(next) > 0),
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
            char_length(name_id) > 0
            AND char_length(name_id) < 32
            AND name_id ~ '^[A-Za-z0-9._+@-]+$'
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

CREATE INDEX IF NOT EXISTS auth_saml_provider_requests_provider_id_idx
    ON auth_saml_provider_requests
    USING btree (provider_id);

CREATE INDEX IF NOT EXISTS auth_saml_provider_requests_user_id_idx
    ON auth_saml_provider_requests
    USING btree (user_id);

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
            AND name_id ~ '^[A-Za-z0-9._+@-]+$'
        ),
    attributes jsonb NOT NULL,
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    updated_at timestamp with time zone NOT NULL DEFAULT now(),

    CONSTRAINT auth_saml_provider_credentials_provider_id_name_id_key
    UNIQUE (provider_id, name_id),

    CONSTRAINT auth_saml_provider_credentials_provider_id_user_id_key
    UNIQUE (provider_id, user_id)
);

CREATE TRIGGER auth_saml_provider_credentials_updated_at
    BEFORE UPDATE ON auth_saml_provider_credentials
    FOR EACH ROW
    EXECUTE FUNCTION set_updated_at();

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

CREATE TRIGGER auth_oauth2_clients_updated_at
    BEFORE UPDATE ON auth_oauth2_clients
    FOR EACH ROW
    EXECUTE FUNCTION set_updated_at();

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

CREATE INDEX IF NOT EXISTS auth_oauth2_client_redirect_uris_client_id_idx 
    ON auth_oauth2_client_redirect_uris
    USING btree (client_id);

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
    scope text
        NOT NULL
        CONSTRAINT auth_oauth2_client_authorization_codes_scope_check
        CHECK (
            char_length(scope) < 512
        ),
    created_at timestamp with time zone
        NOT NULL
        DEFAULT now(),
    expires_at timestamp with time zone
        NOT NULL
        DEFAULT (now() + interval '10 minutes'),
    completed_at timestamp with time zone
);

CREATE INDEX IF NOT EXISTS auth_oauth2_client_authorization_codes_client_id_idx
    ON auth_oauth2_client_authorization_codes
    USING btree (client_id);

CREATE INDEX IF NOT EXISTS auth_oauth2_client_authorization_codes_user_id_idx
    ON auth_oauth2_client_authorization_codes
    USING btree (user_id);

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
    scope text
        NOT NULL
        CONSTRAINT auth_oauth2_client_access_tokens_scope_check
        CHECK (
            char_length(scope) < 512
        ),
    created_at timestamp with time zone
        NOT NULL
        DEFAULT now(),
    expires_at timestamp with time zone
        NOT NULL
        DEFAULT (now() + interval '1 hour')
);

CREATE INDEX IF NOT EXISTS auth_oauth2_client_access_tokens_client_id_idx
    ON auth_oauth2_client_access_tokens
    USING btree (client_id);

CREATE INDEX IF NOT EXISTS auth_oauth2_client_access_tokens_user_id_idx
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
    scope text
        NOT NULL
        CONSTRAINT auth_oauth2_client_refresh_tokens_scope_check
        CHECK (
            char_length(scope) < 512
        ),
    created_at timestamp with time zone
        NOT NULL
        DEFAULT now(),
    expires_at timestamp with time zone
        NOT NULL
        DEFAULT (now() + interval '90 days')
);

CREATE INDEX IF NOT EXISTS auth_oauth2_client_refresh_tokens_client_id_idx
    ON auth_oauth2_client_refresh_tokens
    USING btree (client_id);

CREATE INDEX IF NOT EXISTS auth_oauth2_client_refresh_tokens_user_id_idx
    ON auth_oauth2_client_refresh_tokens
    USING btree (user_id);

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

CREATE INDEX IF NOT EXISTS auth_oauth2_client_consents_client_id_idx
    ON auth_oauth2_client_consents
    USING btree (client_id);
    
CREATE TRIGGER auth_oauth2_client_consents_updated_at
    BEFORE UPDATE ON auth_oauth2_client_consents
    FOR EACH ROW
    EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS auth_jwks (
    id bigint 
        PRIMARY KEY 
        GENERATED ALWAYS AS IDENTITY,
    kid text 
        NOT NULL 
        UNIQUE 
        CONSTRAINT auth_jwks_kid_check 
        CHECK (
            char_length(kid) > 0
        ),
    n text
        NOT NULL
        CHECK (
            char_length(n) > 0
            AND n ~ '^[A-Za-z0-9_-]+$'
        ),
    e text
        NOT NULL
        CHECK (
            char_length(e) > 0
            AND e ~ '^[A-Za-z0-9_-]+$'
        ),
    created_at timestamp with time zone 
        NOT NULL 
        DEFAULT now()
);

CREATE INDEX IF NOT EXISTS auth_jwks_kid_idx
    ON auth_jwks
    USING btree (kid);
