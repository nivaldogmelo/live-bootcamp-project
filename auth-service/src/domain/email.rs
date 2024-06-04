use validator::ValidateEmail;

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct Email(String);

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Email {
    pub fn parse(email: String) -> Result<Email, String> {
        if ValidateEmail::validate_email(&email) {
            Ok(Self(email))
        } else {
            Err(format!("Invalid email {}", email))
        }
    }
}

#[cfg(test)]
extern crate quickcheck;

#[cfg(test)]
mod tests {
    use quickcheck::Gen;

    use super::Email;

    use fake::faker::internet::en::SafeEmail;
    use fake::Fake;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn empty_string() {
        let email = "".to_owned();
        assert!(Email::parse(email).is_err());
    }

    #[test]
    fn missing_domain() {
        let email = "myemaildomainless".to_owned();
        assert!(Email::parse(email).is_err());
    }

    #[test]
    fn missing_subject() {
        let email = "@mydomain".to_owned();
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
        Email::parse(email.0).is_ok()
    }
}
