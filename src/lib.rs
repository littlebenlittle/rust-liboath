use libc::time_t;
use liboath_sys;
use std::ffi::CString;

pub fn totp_generate(secret: String) -> i8 {
    let secret_length = secret.len() as u64;
    let secret = CString::new(secret).expect("key could not be converted to CString");
    let secret_ptr = secret.as_ptr();
    let now = 54321 as time_t;
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
        let secret = "\x31\x32\x33\x34\x35\x36\x37\x38\x39".to_string();
        let output_otp = totp_generate(secret);
        assert_eq!(output_otp, 49 as i8);
    }

}
