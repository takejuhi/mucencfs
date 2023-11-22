use sgx_types::{sgx_enclave_id_t, sgx_status_t};

extern "C" {
    pub(super) fn ecall_test(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        some_string: *const u8,
        len: usize,
    ) -> sgx_status_t;
    pub(super) fn ecall_save_key(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        // db: *mut HashMap<String, String>,
        sub: *const u8,
        sub_len: usize,
        key: *const u8,
        key_len: usize,
    ) -> sgx_status_t;
}
