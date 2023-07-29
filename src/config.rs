use std::net::{IpAddr, SocketAddr};

use axum_sessions::{async_session::SessionStore, SameSite, SessionLayer};
use serde::Deserialize;

use crate::oidc::OidcController;

#[derive(Deserialize, Clone, Debug)]
pub struct CookieConfig {
    name: String,
    domain: String,
    key: String,
}

impl CookieConfig {
    pub fn into_layer<T: SessionStore>(&self, store: T) -> SessionLayer<T> {
        if self.key.len() != 64 {
            panic!("key was not 64 characters");
        }

        SessionLayer::new(store, self.key.as_bytes())
            .with_cookie_domain(self.domain.clone())
            .with_same_site_policy(SameSite::Lax) // todo this should be strict 🤔
            .with_cookie_name(self.name.clone())
            .with_secure(false)
    }
}

#[derive(Deserialize, Clone, Debug)]
pub struct HttpConfig {
    host: String,
    port: usize,
    cookie: CookieConfig,
}

impl HttpConfig {
    pub fn host(&self) -> String {
        self.host.clone()
    }

    pub fn port(&self) -> u16 {
        self.port.try_into().expect("invalid port number")
    }

    pub fn address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    pub fn cookie(&self) -> &CookieConfig {
        &self.cookie
    }
}

impl Into<SocketAddr> for HttpConfig {
    fn into(self) -> SocketAddr {
        let host = IpAddr::parse_ascii(self.host().as_bytes()).expect("failed to parse address");
        let port = self.port();
        return SocketAddr::new(host, port);
    }
}

#[derive(Deserialize, Clone, Debug)]
pub struct OidcProviderConfig {
    client_id: String,
    client_secret: String,
    redirect: String,
}

impl Into<OidcController> for &OidcProviderConfig {
    fn into(self) -> OidcController {
        OidcController::new(
            "https://accounts.google.com".to_string(),
            self.client_id.clone(),
            self.client_secret.clone(),
            self.redirect.clone(),
        )
    }
}

#[derive(Deserialize, Clone, Debug)]
pub struct OidcConfig {
    pub google: OidcProviderConfig,
}

#[derive(Deserialize, Clone, Debug)]
pub struct ServiceConfig {
    pub http: HttpConfig,
    pub oidc: OidcConfig,
}
