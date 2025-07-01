CREATE TABLE IF NOT EXISTS users (
    id bigint
        PRIMARY KEY
        GENERATED ALWAYS AS IDENTITY,
    username text
        NOT NULL
        UNIQUE
        CONSTRAINT users_username_check
        CHECK (char_length(username) >= 3 AND char_length(username) <= 32 AND username ~ '^[a-z][a-z0-9_-]*$'),
    email text
        UNIQUE
        CONSTRAINT users_email_check
        CHECK (email IS NULL OR (char_length(email) >= 3 AND char_length(email) <= 254)),
    is_admin boolean
        NOT NULL
        DEFAULT false,
    first_name text
        CONSTRAINT users_first_name_check
        CHECK (first_name IS NULL OR (char_length(first_name) > 0 AND char_length(first_name) <= 64)),
    last_name text
        CONSTRAINT users_last_name_check
        CHECK (last_name IS NULL OR (char_length(last_name) > 0 AND char_length(last_name) <= 64)),
    created_at timestamp with time zone
        NOT NULL
        DEFAULT now(),
    updated_at timestamp with time zone
        NOT NULL
        DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
    id text
        PRIMARY KEY
        CONSTRAINT sessions_id_check
        CHECK (length(id) = 43),
    user_id bigint
        NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,
    created_at timestamp with time zone
        NOT NULL
        DEFAULT now(),
    expires_at timestamp with time zone
        NOT NULL
        DEFAULT (now() + interval '90 days'),
);

CREATE INDEX IF NOT EXISTS sessions_user_id_key ON sessions USING btree (user_id);

CREATE TABLE IF NOT EXISTS auth_local_credentials (
    user_id bigint
        PRIMARY KEY
        REFERENCES users(id) ON DELETE CASCADE,
    password_hash text
        NOT NULL
        CONSTRAINT auth_local_credentials_password_hash_check
        CHECK (char_length(password_hash) > 0),
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
        CHECK (char_length(slug) >= 3 AND char_length(slug) <= 32 AND slug ~ '^[a-z][a-z0-9-]*$'),
    name text
        NOT NULL
        CONSTRAINT auth_saml_providers_name_check
        CHECK (char_length(name) >= 3),
    metadata_url text NOT NULL CONSTRAINT auth_saml_providers_metadata_url_check CHECK (char_length(metadata_url) > 0),
    sso_url text NOT NULL CONSTRAINT auth_saml_providers_sso_url_check CHECK (char_length(sso_url) > 0),
    certificate text
        NOT NULL
        CONSTRAINT auth_saml_providers_certificate_check
        CHECK (char_length(certificate) > 0),
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

CREATE TABLE IF NOT EXISTS auth_saml_credentials (
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
        CONSTRAINT auth_saml_credentials_name_id_check
        CHECK (char_length(name_id) > 0),
    attributes jsonb NOT NULL,
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    updated_at timestamp with time zone NOT NULL DEFAULT now(),

    CONSTRAINT auth_saml_credentials_provider_id_name_id_key
    UNIQUE (provider_id, name_id),

    CONSTRAINT auth_saml_credentials_provider_id_user_id_key
    UNIQUE (provider_id, user_id)
);

CREATE TABLE IF NOT EXISTS auth_saml_requests (
    id uuid
        PRIMARY KEY,
    user_id bigint
        REFERENCES users(id) ON DELETE CASCADE,
    provider_id bigint
        NOT NULL
        REFERENCES auth_saml_providers(id) ON DELETE CASCADE,
    redirect text
        CONSTRAINT auth_saml_requests_redirect_check
        CHECK (redirect IS NULL OR char_length(redirect) > 0),
    created_at timestamp with time zone
        NOT NULL
        DEFAULT now(),
    completed_at timestamp with time zone,
    name_id text
        CONSTRAINT auth_saml_requests_name_id_check
        CHECK (name_id IS NULL OR char_length(name_id) > 0),
    attributes jsonb,

    CONSTRAINT auth_saml_requests_check
    CHECK (
        (completed_at IS NULL AND name_id IS NULL AND attributes IS NULL)
        OR
        (completed_at IS NOT NULL AND name_id IS NOT NULL AND attributes IS NOT NULL)
    )
);
