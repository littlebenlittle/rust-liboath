use libc::time_t;
use liboath_sys;
use std::ffi::CString;

pub fn totp_generate(secret: &str, now: u32) -> i8 {
    let secret = secret.to_string();
    let secret_length = secret.len() as u64;
    let secret = CString::new(secret).expect("key could not be converted to CString");
    let secret_ptr = secret.as_ptr();
    let now = now as time_t;
    let time_step_size = 30 as u32;
    let start_offset = 0 as i64;
    let digits = 6 as u32;
    let mut output_otp = 0 as i8;
    let ref mut output_otp_ptr = output_otp;
    unsafe {
        liboath_sys::oath_totp_generate(
            secret_ptr,
            secret_length,
            now,
            time_step_size,
            start_offset,
            digits,
            output_otp_ptr,
        );
    }
    return output_otp;
}

#[cfg(test)]
mod tests {

    use crate::*;

    #[test]
    fn it_generates_a_totp() {
        struct Unit {
            secret: &'static str,
            now: u32,
            expects: i8,
        }
        let tests = vec!(
            Unit {
                secret: "\x31\x32\x33\x34\x35\x36\x37\x38\x39",
                now: 54321,
                expects: 49,
            },
            Unit {
                secret: "\x41\x33\x43\x34\x42\x36\x37\x38\x39",
                now: 1000005,
                expects: 51,
            },
            Unit {
                secret: "\x47\x79\x42\x34\x40\x48\x37\x38\x39",
                now: 20005040,
                expects: 57,
            },
        );
        for t in tests {
            let output_otp = totp_generate(t.secret, t.now);
            assert_eq!(output_otp, t.expects);
        }
    }

}
