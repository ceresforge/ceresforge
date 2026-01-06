ALTER TABLE auth_saml_providers 
    ADD COLUMN allow_auto_connection boolean
        NOT NULL
        DEFAULT false;
