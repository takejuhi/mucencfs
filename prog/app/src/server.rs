use anyhow::Result;
use sgx_types::{sgx_enclave_id_t, sgx_status_t};

use crate::{ecall, User};

pub struct Server;

impl Server {
    pub const fn new() -> Self {
        unimplemented!();
    }
    pub fn wait(&mut self) -> Result<()> {
        unimplemented!();
    }
    pub unsafe fn verify(
        &self,
        eid: sgx_enclave_id_t,
        retval: &mut sgx_status_t,
        scratch_pad_pointer: *mut u8,
        scratch_pad_len: usize,
    ) -> sgx_status_t {
        ecall::remote_attestation(eid, retval, scratch_pad_pointer, scratch_pad_len);
        unimplemented!();
    }
    pub fn send_encrypt_key(&self, key: &[u8]) {
        unimplemented!();
    }
    pub(crate) fn get_data(&self) -> User {
        unimplemented!();
    }
}
