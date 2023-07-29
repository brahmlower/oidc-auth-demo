use openidconnect::{
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
    reqwest::async_http_client,
    url::Url,
    ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge, RedirectUrl, Scope,
};

use crate::OidcState;

#[derive(Clone)]
pub struct OidcController {
    issuer_url: String,
    client_id: String,
    client_secret: String,
    redirect: String,
}

impl OidcController {
    pub fn new(
        issuer_url: String,
        client_id: String,
        client_secret: String,
        redirect: String,
    ) -> OidcController {
        OidcController {
            issuer_url,
            client_id,
            client_secret,
            redirect,
        }
    }

    pub async fn new_flow(&self) -> anyhow::Result<(Url, OidcState)> {
        // Use OpenID Connect Discovery to fetch the provider metadata.
        let provider_metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new(self.issuer_url.clone())?,
            async_http_client,
        )
        .await?;

        // Create an OpenID Connect client by specifying the client ID, client secret, authorization URL
        // and token URL.
        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(self.client_id.clone()),
            Some(ClientSecret::new(self.client_secret.clone())),
        )
        // Set the URL the user will be redirected to after the authorization process.
        .set_redirect_uri(RedirectUrl::new(self.redirect.clone())?);

        // Generate a PKCE challenge.
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        // Generate the full authorization URL.
        let (auth_url, csrf_token, nonce) = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            // Set the desired scopes.
            .add_scope(Scope::new("openid".to_string()))
            .add_scope(Scope::new("email".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            // Set the PKCE code challenge.
            .set_pkce_challenge(pkce_challenge)
            .url();

        // This is the URL you should redirect the user to, in order to trigger the authorization
        // process.

        Ok((
            auth_url,
            OidcState {
                client,
                pkce_verifier,
                csrf_token,
                nonce,
            },
        ))
    }
}
