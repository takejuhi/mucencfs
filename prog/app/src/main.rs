// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

use sgx_types::{sgx_enclave_id_t, sgx_status_t};

use crate::server::Server;

extern crate anyhow;
extern crate env_logger;
extern crate once_cell;
extern crate sgx_types;
extern crate sgx_urts;
#[macro_use]
extern crate log;

mod db;
mod ecall;
mod scratch_pad;
mod server;
mod util;

struct User {
    id: String,
    key: String,
}

impl User {
    fn new(id: String, key: String) -> Self {
        trace!("user: {id} was created.");
        Self { id, key }
    }
    unsafe fn save_to_db(
        &self,
        eid: sgx_enclave_id_t,
        retval: &mut sgx_status_t,
        scratch_pad_pointer: *mut u8,
        scratch_pad_len: usize,
    ) -> sgx_status_t {
        ecall::save_key(
            eid,
            retval,
            scratch_pad_pointer,
            scratch_pad_len,
            self.id.as_ptr() as *const u8,
            self.id.len(),
            self.key.as_ptr() as *const u8,
            self.key.len(),
        )
    }
}

fn main() {
    env_logger::init();
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let mut scratch_pad = vec![0u8; scratch_pad::SIZE];
    let scratch_pad_pointer: *mut u8 = &mut scratch_pad[0];
    let enclave = match util::init_enclave() {
        Ok(r) => {
            println!("[+] Init Enclave Successful {}!", r.geteid());
            r
        }
        Err(x) => {
            println!("[-] Init Enclave Failed {}!", x.as_str());
            return;
        }
    };

    let mut server = Server::new();
    loop {
        server.wait();

        match unsafe {
            server.verify(
                enclave.geteid(),
                &mut retval,
                scratch_pad_pointer,
                scratch_pad.len(),
            )
        } {
            sgx_status_t::SGX_SUCCESS => {
                unimplemented!();
            }
            _ => {
                // error
                continue;
            }
        }

        server.send_report();
        let user = server.authentication_request();

        let result = unsafe {
            user.save_to_db(
                enclave.geteid(),
                &mut retval,
                scratch_pad_pointer,
                scratch_pad.len(),
            )
        };
    }

    enclave.destroy();
}
