use openidconnect::{core::CoreGenderClaim, EmptyAdditionalClaims, IdTokenClaims};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Profile {
    pub picture_url: String,
    pub name: String,
    pub email: String,
}

impl Profile {
    pub fn new(picture_url: String, name: String, email: String) -> Profile {
        Profile {
            picture_url,
            name,
            email,
        }
    }
}

impl From<IdTokenClaims<EmptyAdditionalClaims, CoreGenderClaim>> for Profile {
    fn from(claims: IdTokenClaims<EmptyAdditionalClaims, CoreGenderClaim>) -> Profile {
        let picture = claims.picture().unwrap().get(None).unwrap().as_str();
        let name = claims.name().unwrap().get(None).unwrap().as_str();
        let email = claims.email().unwrap().as_str();

        Profile::new(picture.to_string(), name.to_string(), email.to_string())
    }
}
