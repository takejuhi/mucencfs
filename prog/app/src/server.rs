use anyhow::Result;
use sgx_types::{sgx_enclave_id_t, sgx_status_t};

use crate::{ecall, User};

pub struct Server;

impl Server {
    pub const fn new() -> Self {
        unimplemented!("start server");
    }
    pub fn wait(&mut self) -> Result<()> {
        unimplemented!("wait for connection");
    }
    pub unsafe fn verify(
        &self,
        eid: sgx_enclave_id_t,
        retval: &mut sgx_status_t,
        scratch_pad_pointer: *mut u8,
        scratch_pad_len: usize,
    ) -> sgx_status_t {
        ecall::remote_attestation(eid, retval, scratch_pad_pointer, scratch_pad_len);
        unimplemented!("verify this server");
    }
    pub fn send_report(&self) {
        unimplemented!("send attestation report to client");
    }
    pub fn authentication_request(&self) -> User {
        unimplemented!("https://accounts.google.com/o/oauth2/v2/auth?...");
    }
}
