use color_eyre::eyre::{eyre, Context, Result};
use rand::Rng;
use secrecy::{ExposeSecret, Secret};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct LoginAttemptId(Secret<String>);

impl PartialEq for LoginAttemptId {
    fn eq(&self, other: &Self) -> bool {
	self.0.expose_secret() == other.0.expose_secret()
    }
}

impl LoginAttemptId {
    pub fn parse(id: Secret<String>) -> Result<Self> {
	let parsed_id =
	    uuid::Uuid::parse_str(id.expose_secret()).wrap_err("Invalid login attempt id")?;
	let parsed_id = Secret::new(parsed_id.to_string());
	Ok(Self(parsed_id))
    }
}

impl Default for LoginAttemptId {
    fn default() -> Self {
	Self(Secret::new(Uuid::new_v4().to_string()))
    }
}

impl AsRef<Secret<String>> for LoginAttemptId {
    fn as_ref(&self) -> &Secret<String> {
	&self.0
    }
}

#[derive(Debug, Clone)]
pub struct TwoFACode(Secret<String>);

impl PartialEq for TwoFACode {
    fn eq(&self, other: &Self) -> bool {
	self.0.expose_secret() == other.0.expose_secret()
    }
}

impl TwoFACode {
    pub fn parse(code: Secret<String>) -> Result<Self> {
	if code.expose_secret().len() == 6 && code.expose_secret().chars().all(char::is_numeric) {
	    Ok(Self(code))
	} else {
	    Err(eyre!("Invalid 2FA code"))
	}
    }
}

impl Default for TwoFACode {
    fn default() -> Self {
	Self(Secret::new(
	    rand::thread_rng().gen_range(100000..=999999).to_string(),
	))
    }
}

impl AsRef<Secret<String>> for TwoFACode {
    fn as_ref(&self) -> &Secret<String> {
	&self.0
    }
}

#[cfg(test)]
extern crate quickcheck;

#[cfg(test)]
mod tests {
    use quickcheck::Gen;
    use secrecy::Secret;

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
	assert!(TwoFACode::parse(Secret::new(code.to_string())).is_err());
    }

    #[test]
    fn less_than_six_2fa_code() {
	let code = "12345";
	assert!(TwoFACode::parse(Secret::new(code.to_string())).is_err());
    }

    #[test]
    fn not_all_numbers_2fa_code() {
	let code = "1234t2";
	assert!(TwoFACode::parse(Secret::new(code.to_string())).is_err());
    }

    #[test]
    fn test_parse_valid_2fa_code() {
	let code = rand::thread_rng().gen_range(100000..=999999).to_string();
	let code = Secret::new(code);
	assert!(TwoFACode::parse(code).is_ok());
    }

    #[test]
    fn empty_string_login_attempt_id() {
	let code = "";
	let code = Secret::new(code.to_string());
	assert!(LoginAttemptId::parse(code).is_err());
    }

    #[test]
    fn not_uuid_login_attempt_id() {
	let code = "fidoaspnfds-fdas-fdsarg";
	let code = Secret::new(code.to_string());
	assert!(LoginAttemptId::parse(code).is_err());
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
	LoginAttemptId::parse(Secret::new(uuid.0.clone())).is_ok()
    }
}
