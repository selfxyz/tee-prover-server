use std::io;

use aws_nitro_enclaves_nsm_api::{
    api::{ErrorCode, Request, Response},
    driver::nsm_process_request,
};
use p256::elliptic_curve::rand_core::{self, CryptoRng, RngCore};

pub unsafe fn nsm_get_random(fd: i32, buf: *mut u8, buf_len: &mut usize) -> ErrorCode {
    if fd < 0 || buf.is_null() || buf_len == &0 {
        return ErrorCode::InvalidArgument;
    }
    match nsm_process_request(fd, Request::GetRandom) {
        Response::GetRandom { random } => {
            *buf_len = std::cmp::min(*buf_len, random.len());
            unsafe { std::ptr::copy_nonoverlapping(random.as_ptr(), buf, *buf_len) };
            ErrorCode::Success
        }
        Response::Error(err) => err,
        _ => ErrorCode::InvalidResponse,
    }
}

pub struct NitroRng {
    fd: i32, // File descriptor for NitroSecureModule
}

impl NitroRng {
    pub fn new(fd: i32) -> Self {
        Self { fd }
    }
}

impl RngCore for NitroRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        unsafe {
            let mut buf_len = dest.len();
            let res = nsm_get_random(self.fd, dest.as_mut_ptr(), &mut buf_len);
            match res {
                ErrorCode::Success => (),
                _ => panic!("Failed to get random bytes: {:?}", res),
            }
        }
    }

    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        unsafe {
            let mut buf_len = dest.len();
            let res = nsm_get_random(self.fd, dest.as_mut_ptr(), &mut buf_len);
            match res {
                ErrorCode::Success => Ok(()),
                _ => Err(rand_core::Error::new(io::Error::new(
                    io::ErrorKind::Other,
                    "Could not generate random data",
                ))),
            }
        }
    }
}

impl CryptoRng for NitroRng {}
