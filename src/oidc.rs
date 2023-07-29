use openidconnect::{
    core::{CoreAuthenticationFlow, CoreClient, CoreGenderClaim, CoreProviderMetadata},
    reqwest::async_http_client,
    url::Url,
    AccessTokenHash, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EmptyAdditionalClaims,
    IdTokenClaims, IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, Scope, TokenResponse,
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

    pub async fn callback<T>(&self, auth_code: &str, auth_state: &str, oidc_state: &OidcState) -> T
    where
        T: From<IdTokenClaims<EmptyAdditionalClaims, CoreGenderClaim>>,
    {
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

        T::from(claims.clone())
    }
}
