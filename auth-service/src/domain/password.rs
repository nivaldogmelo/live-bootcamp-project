use color_eyre::eyre::{eyre, Result};
use secrecy::{ExposeSecret, Secret};

#[derive(Debug, Clone)]
pub struct Password(Secret<String>);

impl PartialEq for Password {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl AsRef<Secret<String>> for Password {
    fn as_ref(&self) -> &Secret<String> {
        &self.0
    }
}

impl Password {
    pub fn parse(password: Secret<String>) -> Result<Self> {
        if validate_password(&password) {
            Ok(Self(password))
        } else {
            Err(eyre!("Failed to parse string to a Password type"))
        }
    }
}

fn validate_password(s: &Secret<String>) -> bool {
    s.expose_secret().len() >= 8
}

#[cfg(test)]
extern crate quickcheck;

#[cfg(test)]
mod tests {
    use quickcheck::Gen;

    use super::Password;

    use fake::faker::internet::en::Password as FakePassword;
    use fake::Fake;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use secrecy::Secret;

    #[test]
    fn empty_string() {
        let pass = Secret::new("".to_string());
        assert!(Password::parse(pass).is_err());
    }

    #[test]
    fn less_than_8_chars() {
        let pass = Secret::new("1234567".to_string());
        assert!(Password::parse(pass).is_err());
    }

    #[derive(Debug, Clone)]
    struct ValidPassword(pub Secret<String>);

    impl quickcheck::Arbitrary for ValidPassword {
        fn arbitrary(g: &mut Gen) -> Self {
            let mut rng = StdRng::seed_from_u64(u64::arbitrary(g));
            let pass = FakePassword(8..50).fake_with_rng(&mut rng);
            Self(Secret::new(pass))
        }
    }

    #[quickcheck]
    fn test_parse_valid(pass: ValidPassword) -> bool {
        Password::parse(pass.0).is_ok()
    }
}
