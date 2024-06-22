use color_eyre::eyre::{eyre, Context, Result};
use rand::Rng;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq)]
pub struct LoginAttemptId(String);

impl LoginAttemptId {
    pub fn parse(id: String) -> Result<Self> {
        let parsed_id = uuid::Uuid::parse_str(&id).wrap_err("Invalid login attempt id")?;
        Ok(Self(parsed_id.to_string()))
    }
}

impl Default for LoginAttemptId {
    fn default() -> Self {
        Self(Uuid::new_v4().to_string())
    }
}

impl AsRef<str> for LoginAttemptId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TwoFACode(String);

impl TwoFACode {
    pub fn parse(code: String) -> Result<Self> {
        if code.len() == 6 && code.chars().all(char::is_numeric) {
            Ok(Self(code))
        } else {
            Err(eyre!("Invalid 2FA code"))
        }
    }
}

impl Default for TwoFACode {
    fn default() -> Self {
        Self(rand::thread_rng().gen_range(100000..=999999).to_string())
    }
}

impl AsRef<str> for TwoFACode {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
extern crate quickcheck;

#[cfg(test)]
mod tests {
    use quickcheck::Gen;

    use super::LoginAttemptId;
    use super::TwoFACode;

    use fake::uuid::UUIDv4 as FakeUUIDv4;
    use fake::Fake;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;

    #[test]
    fn empty_string_2fa_code() {
        let code = "";
        assert!(TwoFACode::parse(code.to_string()).is_err());
    }

    #[test]
    fn less_than_six_2fa_code() {
        let code = "12345";
        assert!(TwoFACode::parse(code.to_string()).is_err());
    }

    #[test]
    fn not_all_numbers_2fa_code() {
        let code = "1234t2";
        assert!(TwoFACode::parse(code.to_string()).is_err());
    }

    #[test]
    fn test_parse_valid_2fa_code() {
        let code = rand::thread_rng().gen_range(100000..=999999).to_string();
        assert!(TwoFACode::parse(code).is_ok());
    }

    #[test]
    fn empty_string_login_attempt_id() {
        let code = "";
        assert!(LoginAttemptId::parse(code.to_string()).is_err());
    }

    #[test]
    fn not_uuid_login_attempt_id() {
        let code = "fidoaspnfds-fdas-fdsarg";
        assert!(LoginAttemptId::parse(code.to_string()).is_err());
    }

    #[derive(Debug, Clone)]
    struct ValidLoginAttemptId(pub String);

    impl quickcheck::Arbitrary for ValidLoginAttemptId {
        fn arbitrary(g: &mut Gen) -> Self {
            let mut rng = StdRng::seed_from_u64(u64::arbitrary(g));
            let uuid = FakeUUIDv4.fake_with_rng(&mut rng);
            Self(uuid)
        }
    }

    #[quickcheck]
    fn test_parse_valid_valid_login_attempt_id(uuid: ValidLoginAttemptId) -> bool {
        LoginAttemptId::parse(uuid.0.clone()).is_ok()
    }
}
