use anyhow::Result;
use sgx_types::{sgx_enclave_id_t, sgx_status_t};

use crate::{ecall, User};

pub struct Server;

impl Server {
    pub const fn new() -> Result<Self> {
        let listener = TcpListener::bind("localhost:5432")?;
        Ok(listener)
    }
    pub fn wait(&mut self) -> Result<()> {
        let stream = listener.accept()?;
        println!("addr: {}", stream.1);

        let mut stream = stream.0;
        let mut buf = [0u8; 1024];
        let size = stream.read(&mut buf)?;

        if size = 0 {
            continue;
        }

        let data = String::from_utf8(buf.to_vec())?;
        println!("{data}");

        if let Err(e) = stream.write(b"hello") {
            eprintln!("fail to write");
        }
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
