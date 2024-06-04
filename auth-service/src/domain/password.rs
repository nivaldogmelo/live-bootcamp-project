#[derive(Debug, PartialEq, Clone)]
pub struct Password(String);

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Password {
    pub fn parse(password: String) -> Result<Password, String> {
        if password.len() >= 8 {
            Ok(Password(password))
        } else {
            Err(format!(
                "Password must be at least 8 characters long, but was {} characters long",
                password.len()
            ))
        }
    }
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

    #[test]
    fn empty_string() {
        let pass = "".to_owned();
        assert!(Password::parse(pass).is_err());
    }

    #[test]
    fn less_than_8_chars() {
        let pass = "1234567".to_owned();
        assert!(Password::parse(pass).is_err());
    }

    #[derive(Debug, Clone)]
    struct ValidPassword(pub String);

    impl quickcheck::Arbitrary for ValidPassword {
        fn arbitrary(g: &mut Gen) -> Self {
            let mut rng = StdRng::seed_from_u64(u64::arbitrary(g));
            let pass = FakePassword(8..50).fake_with_rng(&mut rng);
            Self(pass)
        }
    }

    #[quickcheck]
    fn test_parse_valid(pass: ValidPassword) -> bool {
        Password::parse(pass.0).is_ok()
    }
}
