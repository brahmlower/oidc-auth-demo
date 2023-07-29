use std::collections::HashMap;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use axum_sessions::extractors::{ReadableSession, WritableSession};

use crate::{components::page_index, models::Profile, AppState};

pub async fn handler_root(session: ReadableSession) -> Response<String> {
    let profile: Option<Profile> = session.get("profile");

    let body = page_index(profile);
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/html")
        .body(body)
        .unwrap()
}

pub async fn handler_oidc_google(State(state): State<AppState>) -> Response {
    let (url, oidc_state) = state
        .oidc_controller
        .new_flow()
        .await
        .expect("failed to start oidc flow");

    let mut inner_oidc_state = state.oidc_state.lock().await;
    *inner_oidc_state = Some(oidc_state);

    Redirect::to(url.as_str()).into_response()
}

pub async fn handler_oidc_callback(
    query_params: Query<HashMap<String, String>>,
    mut session: WritableSession,
    State(state): State<AppState>,
) -> Response {
    let auth_code = query_params
        .get("code")
        .expect("missing code query parameter");
    let auth_state = query_params
        .get("state")
        .expect("missing csrf state parameter");

    let inner_state = state.oidc_state.lock().await;
    let oidc_state = inner_state.as_ref().expect("no oidc flow in progress");

    let profile: Profile = state
        .oidc_controller
        .callback(auth_code, auth_state, oidc_state)
        .await;

    session
        .insert("profile", profile)
        .expect("failed to insert profile");

    Redirect::to("/").into_response()
}
