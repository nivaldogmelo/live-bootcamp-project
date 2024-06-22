use core::hash::Hash;
use std::hash::Hasher;

use color_eyre::eyre::{eyre, Result};
use secrecy::{ExposeSecret, Secret};
use validator::ValidateEmail;

#[derive(Debug, Clone)]
pub struct Email(Secret<String>);

impl Hash for Email {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.expose_secret().hash(state);
    }
}

impl Eq for Email {}

impl PartialEq for Email {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl AsRef<Secret<String>> for Email {
    fn as_ref(&self) -> &Secret<String> {
        &self.0
    }
}

impl Email {
    pub fn parse(email: Secret<String>) -> Result<Self> {
        if ValidateEmail::validate_email(&email.expose_secret()) {
            Ok(Self(email))
        } else {
            Err(eyre!("Invalid email {}", email.expose_secret()))
        }
    }
}

#[cfg(test)]
extern crate quickcheck;

#[cfg(test)]
mod tests {
    use quickcheck::Gen;
    use secrecy::Secret;

    use super::Email;

    use fake::faker::internet::en::SafeEmail;
    use fake::Fake;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn empty_string() {
        let email = "".to_owned();
        let email = Secret::new(email);
        assert!(Email::parse(email).is_err());
    }

    #[test]
    fn missing_domain() {
        let email = "myemaildomainless".to_owned();
        let email = Secret::new(email);
        assert!(Email::parse(email).is_err());
    }

    #[test]
    fn missing_subject() {
        let email = "@mydomain".to_owned();
        let email = Secret::new(email);
        assert!(Email::parse(email).is_err());
    }

    #[derive(Debug, Clone)]
    struct ValidEmail(pub String);

    impl quickcheck::Arbitrary for ValidEmail {
        fn arbitrary(g: &mut Gen) -> Self {
            let mut rng = StdRng::seed_from_u64(u64::arbitrary(g));
            let email = SafeEmail().fake_with_rng(&mut rng);
            Self(email)
        }
    }

    #[quickcheck]
    fn test_parse_valid(email: ValidEmail) -> bool {
        Email::parse(Secret::new(email.0)).is_ok()
    }
}
