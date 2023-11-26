use sgx_types::sgx_status_t;

extern "C" {
    pub fn save_to_db(
        retval: *mut sgx_status_t,
        key_pointer: *mut u8,
        key_size: usize,
        scratch_pad_pointer: *mut u8,
        sealed_log_size: usize,
    ) -> sgx_status_t;
    pub fn get_from_db(
        retval: *mut sgx_status_t,
        key_pointer: *mut u8,
        key_size: usize,
        value_pointer: *mut u8,
        value_size: usize,
    ) -> sgx_status_t;
}