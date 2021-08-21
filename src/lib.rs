use libc::{c_char, c_uint, time_t};
use liboath_sys;
use std::ffi::{CStr, CString};

use secrets::SecretVec;

pub enum Digits {
    Six,
    Seven,
    Eight,
}

#[derive(Clone, PartialEq)]
pub struct TotpSecret {
    inner: SecretVec<u8>,
}

impl From<SecretVec<u8>> for TotpSecret {
    fn from(inner: SecretVec<u8>) -> TotpSecret {
        TotpSecret { inner }
    }
}

impl From<String> for TotpSecret {
    fn from(secret_key: String) -> TotpSecret {
        let mut bytes: Vec<u8> = secret_key.into();
        SecretVec::from(&mut bytes[..]).into()
    }
}

impl Into<String> for TotpSecret {
    fn into(self) -> String {
        let secret = self.inner.borrow().to_vec();
        std::str::from_utf8(&secret[..]).unwrap().to_owned()
    }
}

pub fn totp_generate(
    totp_secret: &TotpSecret,
    now: liboath_sys::time_t,
    time_step_size: c_uint,
    start_offset: liboath_sys::time_t,
    digits: Digits,
) -> String {
    let secret: Vec<u8> = totp_secret.inner.borrow().to_vec();
    let secret_length = secret.len() as liboath_sys::size_t;
    let secret = CString::new(secret).expect("key could not be converted to CString");
    let secret_ptr = secret.as_ptr();
    let digits = match digits {
        Digits::Six => 6,
        Digits::Seven => 7,
        Digits::Eight => 8,
    };
    let now = now as time_t;
    let mut output_otp: Vec<c_char> = vec![0; digits as usize + 1];
    let output_otp_ptr = output_otp.as_mut_ptr();
    unsafe {
        let result = liboath_sys::oath_totp_generate(
            secret_ptr,
            secret_length,
            now,
            time_step_size,
            start_offset,
            digits,
            output_otp_ptr,
        );
        if result != liboath_sys::oath_rc_OATH_OK {
            panic!("liboath error: {}", result);
        }
        CStr::from_ptr(output_otp_ptr).to_str().unwrap().to_owned()
    }
}

#[cfg(test)]
mod tests {

    use crate::*;

    #[test]
    fn it_generates_a_totp() {
        struct Unit {
            digits: Digits,
            expects: String,
        }
        let tests = vec![
            Unit {
                digits: Digits::Six,
                expects: "944687".into(),
            },
            Unit {
                digits: Digits::Seven,
                expects: "8944687".into(),
            },
            Unit {
                digits: Digits::Eight,
                expects: "38944687".into(),
            },
        ];
        for t in tests {
            let secret = "\x47\x79\x42\x34\x40\x48\x37\x38\x39".to_owned().into();
            let now = 20005041;
            let time_step_size = 30;
            let start_offset = 0;
            let output_otp = totp_generate(&secret, now, time_step_size, start_offset, t.digits);
            assert_eq!(output_otp, t.expects);
        }
    }

    #[test]
    fn it_converts_between_totpsecret_and_string() {
        let i: String = "somevalue".to_owned();
        let secret: TotpSecret = i.clone().into();
        let o: String = secret.into();
        assert_eq!(i, o);
    }

}
