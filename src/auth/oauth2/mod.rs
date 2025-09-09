use crate::{AppState, auth::login_required_uri, base, frontend::FrontendResult, record::User};
use axum::{
    Router,
    extract::{Form, OriginalUri, Path, Query, State},
    http::{HeaderMap, StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use maud::html;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct AuthorizeParams {
    response_type: String,
    client_id: String,
    redirect_uri: Option<String>,
    scope: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Payload {
    action: String,
}

fn generate_authorization_code() -> String {
    generate_secure_string!(16)
}

fn generate_client_id() -> String {
    generate_secure_string!(24)
}

fn generate_client_secret() -> String {
    generate_secure_string!(32)
}

fn authorize_form(path_and_query: &str) -> Response {
    let title = "Authorize";
    let description = "Allow?";
    html! {
        (base(&title, description, html! {
            div .full-screen {
                h1 {
                    (title)
                }
                p {
                    (description)
                }
                form method="POST" action=(path_and_query) {
                    div {
                        button type="submit" name="action" value="allow" { "Allow" }
                        button type="submit" name="action" value="deny" class="red-bg" { "Deny" }
                    }
                }
            }
        }))
    }
    .into_response()
}

async fn authorize_get(user: Option<User>, uri: OriginalUri) -> FrontendResult<Response> {
    let path_and_query = uri.path_and_query().unwrap().as_str();
    if user.is_none() {
        return Ok(Redirect::temporary(&login_required_uri(path_and_query, &user)).into_response());
    }
    Ok(authorize_form(path_and_query))
}

async fn authorize_post(
    State(state): State<AppState>,
    user: Option<User>,
    uri: OriginalUri,
    Query(params): Query<AuthorizeParams>,
    Form(payload): Form<Payload>,
) -> FrontendResult<Response> {
    let path_and_query = uri.path_and_query().unwrap().as_str();
    if user.is_none() {
        return Ok(Redirect::temporary(&login_required_uri(path_and_query, &user)).into_response());
    }
    let authorization_code = generate_authorization_code();
    if payload.action != "allow" {
        return Ok("Denied".into_response());
    }
    Ok("Authorize".into_response())
}

async fn token(State(state): State<AppState>, user: Option<User>) -> FrontendResult<Response> {
    Ok("Token".into_response())
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/authorize", get(authorize_get).post(authorize_post))
        .route("/token", post(token))
}
