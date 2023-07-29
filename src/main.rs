#![feature(addr_parse_ascii)]

mod components;
mod config;
mod handlers;
mod models;
mod oidc;

use std::sync::Arc;

use axum::{routing, Router};
use axum_sessions::async_session;
use figment::providers::{Env, Format, Toml};
use figment::Figment;
use oidc::OidcController;
use openidconnect::core::CoreClient;
use openidconnect::{CsrfToken, Nonce, PkceCodeVerifier};
use tokio::sync::Mutex;

use crate::config::ServiceConfig;

pub struct OidcState {
    client: CoreClient,
    pkce_verifier: PkceCodeVerifier,
    csrf_token: CsrfToken,
    nonce: Nonce,
}

#[derive(Clone)]
pub struct AppState {
    oidc_controller: OidcController,
    oidc_state: Arc<Mutex<Option<OidcState>>>,
}

#[tokio::main]
async fn main() {
    let config: ServiceConfig = Figment::new()
        .merge(Toml::file("service.toml"))
        .merge(Env::prefixed("APP_").split("_"))
        .extract()
        .unwrap();

    let store = async_session::MemoryStore::new();
    let state = AppState {
        oidc_controller: (&config.oidc.google).into(),
        oidc_state: Arc::new(Mutex::new(None)),
    };

    let app = Router::new()
        .route(
            "/auth/oidc/google",
            routing::get(handlers::handler_oidc_google),
        )
        .route(
            "/auth/oidc/redirect",
            routing::get(handlers::handler_oidc_callback),
        )
        .route("/", routing::get(handlers::handler_root))
        .layer(config.http.cookie().into_layer(store))
        .with_state(state);

    println!("Listening at {}!", config.http.address());
    axum::Server::bind(&config.http.into())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
