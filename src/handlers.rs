use std::collections::HashMap;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use axum_sessions::extractors::{ReadableSession, WritableSession};
use openidconnect::{
    reqwest::async_http_client, AccessTokenHash, AuthorizationCode, OAuth2TokenResponse,
    PkceCodeVerifier, TokenResponse,
};

use crate::{components::page_index, models::Profile, AppState};

pub async fn handler_root(
    session: ReadableSession,
    State(state): State<AppState>,
) -> Response<String> {
    let profile = if session.get::<String>("name").is_some() {
        let picture = session.get("picture").unwrap_or("None".to_owned());
        let name = session.get("name").unwrap_or("None".to_owned());
        let email = session.get("email").unwrap_or("None".to_owned());

        Some(Profile::new(picture, name, email))
    } else {
        None
    };

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

    if auth_state != oidc_state.csrf_token.secret() {
        panic!(
            "auth_state ({}) does not match expected csrf_token ({})",
            auth_state,
            oidc_state.csrf_token.secret()
        );
    }

    // Once the user has been redirected to the redirect URL, you'll have access to the
    // authorization code. For security reasons, your code should verify that the `state`
    // parameter returned by the server matches `csrf_state`.

    let owned_verifier = PkceCodeVerifier::new(oidc_state.pkce_verifier.secret().to_owned());

    // Now you can exchange it for an access token and ID token.
    let token_response = oidc_state
        .client
        .exchange_code(AuthorizationCode::new(auth_code.to_string()))
        // Set the PKCE code verifier.
        .set_pkce_verifier(owned_verifier)
        .request_async(async_http_client)
        .await
        .expect("response token failed");

    // Extract the ID token claims after verifying its authenticity and nonce.
    let id_token = token_response
        .id_token()
        .expect("Server did not return an ID token");
    let claims = id_token
        .claims(&oidc_state.client.id_token_verifier(), &oidc_state.nonce)
        .expect("claims failed");

    // Verify the access token hash to ensure that the access token hasn't been substituted for
    // another user's.
    if let Some(expected_access_token_hash) = claims.access_token_hash() {
        let actual_access_token_hash = AccessTokenHash::from_token(
            token_response.access_token(),
            &id_token.signing_alg().expect("signing alg was not okay"),
        )
        .expect("access token from hash failed");
        if actual_access_token_hash != *expected_access_token_hash {
            panic!("invalid access token");
        }
    }

    // The authenticated user's identity is now available. See the IdTokenClaims struct for a
    // complete listing of the available claims.
    // println!(
    //     "User {} with e-mail address {} has authenticated successfully",
    //     claims.subject().as_str(),
    //     claims.email().map(|email| email.as_str()).unwrap_or("<not provided>"),
    // );

    // set the session here and then redirect back to home

    let picture = claims.picture().unwrap().get(None).unwrap().as_str();
    let name = claims.name().unwrap().get(None).unwrap().as_str();
    let email = claims.email().unwrap().as_str();

    session
        .insert("picture", picture)
        .expect("failed to insert picture");
    session.insert("name", name).expect("failed to insert name");
    session
        .insert("email", email)
        .expect("failed to insert email");

    Redirect::to("/").into_response()

    // let body = format!("
    //     <html>
    //         <img src=\"{}\">
    //         <p>{} ({})</p>
    //     </html>
    //     ",
    //     claims.picture().unwrap().get(None).unwrap().as_str(),
    //     claims.name().unwrap().get(None).unwrap().as_str(),
    //     claims.email().unwrap().as_str(),
    // );

    // Response::builder()
    //     .status(StatusCode::TEMPORARY_REDIRECT)
    //     .header("Content-Type", "text/html")
    //     .body(body)
    //     .unwrap()
}
