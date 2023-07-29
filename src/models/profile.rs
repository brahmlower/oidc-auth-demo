
pub struct Profile {
    pub picture_url: String,
    pub name: String,
    pub email: String,
}

impl Profile {
    pub fn new(picture_url: String, name: String, email: String) -> Profile {
        Profile {
            picture_url, name, email
        }
    }
}
