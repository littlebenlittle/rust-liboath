use liboath_sys;
use libc::{c_char, c_uint, time_t};
use std::ffi::{CStr, CString};

pub type OathError = String;
pub type Result<T> = std::result::Result<T, OathError>;

pub enum Digits {
    Six,
    Seven,
    Eight,
}

pub fn totp_generate(
    secret: &str,
    now: liboath_sys::time_t,
    time_step_size: c_uint,
    start_offset: liboath_sys::time_t,
    digits: Digits,
) -> String {
    let secret = secret.to_string();
    let secret_length = secret.len() as liboath_sys::size_t;
    let secret = CString::new(secret).expect("key could not be converted to CString");
    let secret_ptr = secret.as_ptr();
    let digits = match digits {
        Digits::Six => 6,
        Digits::Seven => 7,
        Digits::Eight => 8,
    };
    let now = now as time_t;
    let mut output_otp: Vec<c_char> = vec!(0; digits as usize + 1);
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
            let secret = "\x47\x79\x42\x34\x40\x48\x37\x38\x39";
            let now = 20005041;
            let time_step_size = 30;
            let start_offset = 0;
            let output_otp = totp_generate(secret, now, time_step_size, start_offset, t.digits);
            assert_eq!(output_otp, t.expects);
        }
    }
}
