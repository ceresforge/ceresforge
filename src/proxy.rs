use axum::http::header;

const ALLOWED_REQUEST_HEADERS: &[header::HeaderName] = &[
    header::ACCEPT,
    header::ACCEPT_ENCODING,
    header::ACCEPT_LANGUAGE,
    header::CACHE_CONTROL,
    header::CONTENT_TYPE,
    header::COOKIE, // Allowed so SvelteKit can read session data
    header::HOST,
    header::USER_AGENT,
];
