use sgx_types::{sgx_enclave_id_t, sgx_status_t};

extern "C" {
    pub fn save_key(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        scratch_pad_pointer: *mut u8,
        _scratch_pad_pointer: usize,
        sub: *const u8,
        sub_len: usize,
        key: *const u8,
        key_len: usize,
    ) -> sgx_status_t;
}
