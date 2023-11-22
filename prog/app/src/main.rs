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

extern crate once_cell;
extern crate sgx_types;
extern crate sgx_urts;

mod db;
mod ecall;
mod util;

use db::DATABASE;
use ecall::{ecall_save_key, ecall_test};
use sgx_types::*;
use util::init_enclave;

fn main() {
    let enclave = match init_enclave() {
        Ok(r) => {
            println!("[+] Init Enclave Successful {}!", r.geteid());
            r
        }
        Err(x) => {
            println!("[-] Init Enclave Failed {}!", x.as_str());
            return;
        }
    };

    // let mut db = HashMap::new();

    // let input_string = String::from("Sending this string to the enclave then printing it\n");
    let sub = String::from("alice@gmail.com");
    let key = String::from("alice-key");

    let mut retval = sgx_status_t::SGX_SUCCESS;

    let result = unsafe {
        ecall_save_key(
            enclave.geteid(),
            &mut retval,
            // &mut db as *mut HashMap<String, String>,
            sub.as_ptr() as *const u8,
            sub.len(),
            key.as_ptr() as *const u8,
            key.len(),
        )
    };

    match result {
        sgx_status_t::SGX_SUCCESS => {}
        _ => {
            println!("[-] ECALL Enclave Failed {}!", result.as_str());
            return;
        }
    }

    println!("[+] ecall_test success...");

    enclave.destroy();
}
