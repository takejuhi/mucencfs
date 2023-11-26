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

struct Item {
    id: Vec<u8>,
    key: Vec<u8>,
    sign: Vec<u8>,
}

impl Item {
    fn new(id: &[u8], key: &[u8]) -> Self {
        let sign = Vec::new();
        unimplemented!();
        Self {
            id: id.to_vec(),
            key: key.to_vec(),
            sign,
        }
    }
}

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
    let id = unsafe { slice::from_raw_parts(id, id_size) };
    let key = unsafe { slice::from_raw_parts(key, key_size) };
    let item = Item::new(id, key);

    let encoded_item = serde_cbor::to_vec(&item).unwarp();
    let encoded_item_slice = encoded_item.as_slice();
    let extra_data = [0u8; 0];

    let sealed_data = match SgxSealedData::<[u8]>::seal_data(&extra_data, encoded_item_slice) {
        Ok(sealed_data) => sealed_data,
        Err(sgx_error) => return sgx_error;
    };
    let sealed_log_size = size_of::<sgx_sealed_data_t>() + encoded_item_slice.len();

    let _option = unsafe { sealed_data.to_raw_sealed_data_t(scratch_pad_pointer as *mut sgx_sealed_data_t, sealed_log_size as u32) };

    unsafe { ocall::save_to_db(&mut retval, id, id_size, scratch_pad_pointer, sealed_log_size as usize) };

    retval
}
