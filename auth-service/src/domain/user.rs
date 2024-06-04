use super::{Email, Password};

#[derive(Debug, PartialEq, Clone)]
pub struct User {
    pub email: Email,
    pub password: Password,
    pub requires_2fa: bool,
}

impl User {
    pub fn new(email: Email, password: Password, requires_2fa: bool) -> User {
        User {
            email,
            password,
            requires_2fa,
        }
    }
}
