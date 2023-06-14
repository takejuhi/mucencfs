#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "time.h"
#include "stdint.h"
#include "stdbool.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

int ecall_test(const char* message, size_t message_len);
sgx_status_t ecall_start_tls_server(void);
sgx_status_t ecall_main(void);
uint32_t get_sealed_data_size(uint32_t data_size);

sgx_status_t SGX_CDECL ocall_print(const char* str);
sgx_status_t SGX_CDECL uprint(const char* str);
sgx_status_t SGX_CDECL usgx_exit(int reason);
sgx_status_t SGX_CDECL print_log(long int start, long int end, size_t len);
sgx_status_t SGX_CDECL print_error_message(sgx_status_t ret);
sgx_status_t SGX_CDECL get_system_time(long int* retval);
sgx_status_t SGX_CDECL read_file_to_buf(sgx_status_t* retval, const char* filename, uint8_t* buf, size_t bsize);
sgx_status_t SGX_CDECL write_buf_to_file(sgx_status_t* retval, const char* filename, const uint8_t* buf, size_t bsize, long int offset);
sgx_status_t SGX_CDECL get_file_size(size_t* retval, const char* filename, size_t len);
sgx_status_t SGX_CDECL ocall_WritePublicKeyFile(sgx_status_t* retval, const char* user_id, const char* key_str, size_t len);
sgx_status_t SGX_CDECL ocall_ReadPublicKeyFile(sgx_status_t* retval, const char* user_id, char* key_str, size_t len);
sgx_status_t SGX_CDECL ocall_existsPublicKeyFile(sgx_status_t* retval, const char* user_id, size_t id_size);
sgx_status_t SGX_CDECL ocall_sgx_clock(long int* retval);
sgx_status_t SGX_CDECL ocall_sgx_time(time_t* retval, time_t* timep, int t_len);
sgx_status_t SGX_CDECL ocall_sgx_localtime(struct tm** retval, const time_t* timep, int t_len);
sgx_status_t SGX_CDECL ocall_sgx_gmtime_r(struct tm** retval, const time_t* timep, int t_len, struct tm* tmp, int tmp_len);
sgx_status_t SGX_CDECL ocall_sgx_gettimeofday(int* retval, void* tv, int tv_size);
sgx_status_t SGX_CDECL ocall_sgx_getsockopt(int* retval, int s, int level, int optname, char* optval, int optval_len, int* optlen);
sgx_status_t SGX_CDECL ocall_sgx_setsockopt(int* retval, int s, int level, int optname, const void* optval, int optlen);
sgx_status_t SGX_CDECL ocall_sgx_socket(int* retval, int af, int type, int protocol);
sgx_status_t SGX_CDECL ocall_sgx_listen(int* retval, int s, int backlog);
sgx_status_t SGX_CDECL ocall_sgx_bind(int* retval, int s, const void* addr, int addr_size);
sgx_status_t SGX_CDECL ocall_sgx_connect(int* retval, int s, const void* addr, int addrlen);
sgx_status_t SGX_CDECL ocall_sgx_accept(int* retval, int s, void* addr, int addr_size, int* addrlen);
sgx_status_t SGX_CDECL ocall_sgx_shutdown(int* retval, int fd, int how);
sgx_status_t SGX_CDECL ocall_sgx_read(int* retval, int fd, void* buf, int n);
sgx_status_t SGX_CDECL ocall_sgx_write(int* retval, int fd, const void* buf, int n);
sgx_status_t SGX_CDECL ocall_sgx_close(int* retval, int fd);
sgx_status_t SGX_CDECL ocall_sgx_getenv(int* retval, const char* env, int envlen, char* ret_str, int ret_len);
sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
