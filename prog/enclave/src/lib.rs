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

#![crate_name = "sample"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_types;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

mod ocall;

use sgx_types::*;
use std::io::{self, Write};
use std::slice;
use std::string::String;

#[no_mangle]
pub extern "C" fn save_key(
    scratch_pad_pointer: *mut u8,
    _scratch_pad_size: usize,
    id: *const u8,
    id_size: usize,
    key: *const u8,
    key_len: usize,
) -> sgx_status_t {
    let mut retval = sgx_status_t::SGX_SUCCESS;
    /*
    TODO: sealing
    ocall::save_to_db(&mut retval, id, id_size, scratch_pad_pointer, k)
    */
}
