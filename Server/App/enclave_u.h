#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "time.h"
#include "stdint.h"
#include "stdbool.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_PRINT_DEFINED__
#define OCALL_PRINT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print, (const char* str));
#endif
#ifndef UPRINT_DEFINED__
#define UPRINT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, uprint, (const char* str));
#endif
#ifndef USGX_EXIT_DEFINED__
#define USGX_EXIT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, usgx_exit, (int reason));
#endif
#ifndef PRINT_LOG_DEFINED__
#define PRINT_LOG_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, print_log, (long int start, long int end, size_t len));
#endif
#ifndef PRINT_ERROR_MESSAGE_DEFINED__
#define PRINT_ERROR_MESSAGE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, print_error_message, (sgx_status_t ret));
#endif
#ifndef GET_SYSTEM_TIME_DEFINED__
#define GET_SYSTEM_TIME_DEFINED__
long int SGX_UBRIDGE(SGX_NOCONVENTION, get_system_time, (void));
#endif
#ifndef READ_FILE_TO_BUF_DEFINED__
#define READ_FILE_TO_BUF_DEFINED__
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, read_file_to_buf, (const char* filename, uint8_t* buf, size_t bsize));
#endif
#ifndef WRITE_BUF_TO_FILE_DEFINED__
#define WRITE_BUF_TO_FILE_DEFINED__
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, write_buf_to_file, (const char* filename, const uint8_t* buf, size_t bsize, long int offset));
#endif
#ifndef GET_FILE_SIZE_DEFINED__
#define GET_FILE_SIZE_DEFINED__
size_t SGX_UBRIDGE(SGX_NOCONVENTION, get_file_size, (const char* filename, size_t len));
#endif
#ifndef OCALL_WRITEPUBLICKEYFILE_DEFINED__
#define OCALL_WRITEPUBLICKEYFILE_DEFINED__
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_WritePublicKeyFile, (const char* user_id, const char* key_str, size_t len));
#endif
#ifndef OCALL_READPUBLICKEYFILE_DEFINED__
#define OCALL_READPUBLICKEYFILE_DEFINED__
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_ReadPublicKeyFile, (const char* user_id, char* key_str, size_t len));
#endif
#ifndef OCALL_EXISTSPUBLICKEYFILE_DEFINED__
#define OCALL_EXISTSPUBLICKEYFILE_DEFINED__
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_existsPublicKeyFile, (const char* user_id, size_t id_size));
#endif
#ifndef OCALL_SGX_CLOCK_DEFINED__
#define OCALL_SGX_CLOCK_DEFINED__
long int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_clock, (void));
#endif
#ifndef OCALL_SGX_TIME_DEFINED__
#define OCALL_SGX_TIME_DEFINED__
time_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_time, (time_t* timep, int t_len));
#endif
#ifndef OCALL_SGX_LOCALTIME_DEFINED__
#define OCALL_SGX_LOCALTIME_DEFINED__
struct tm* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_localtime, (const time_t* timep, int t_len));
#endif
#ifndef OCALL_SGX_GMTIME_R_DEFINED__
#define OCALL_SGX_GMTIME_R_DEFINED__
struct tm* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_gmtime_r, (const time_t* timep, int t_len, struct tm* tmp, int tmp_len));
#endif
#ifndef OCALL_SGX_GETTIMEOFDAY_DEFINED__
#define OCALL_SGX_GETTIMEOFDAY_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_gettimeofday, (void* tv, int tv_size));
#endif
#ifndef OCALL_SGX_GETSOCKOPT_DEFINED__
#define OCALL_SGX_GETSOCKOPT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_getsockopt, (int s, int level, int optname, char* optval, int optval_len, int* optlen));
#endif
#ifndef OCALL_SGX_SETSOCKOPT_DEFINED__
#define OCALL_SGX_SETSOCKOPT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_setsockopt, (int s, int level, int optname, const void* optval, int optlen));
#endif
#ifndef OCALL_SGX_SOCKET_DEFINED__
#define OCALL_SGX_SOCKET_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_socket, (int af, int type, int protocol));
#endif
#ifndef OCALL_SGX_LISTEN_DEFINED__
#define OCALL_SGX_LISTEN_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_listen, (int s, int backlog));
#endif
#ifndef OCALL_SGX_BIND_DEFINED__
#define OCALL_SGX_BIND_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_bind, (int s, const void* addr, int addr_size));
#endif
#ifndef OCALL_SGX_CONNECT_DEFINED__
#define OCALL_SGX_CONNECT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_connect, (int s, const void* addr, int addrlen));
#endif
#ifndef OCALL_SGX_ACCEPT_DEFINED__
#define OCALL_SGX_ACCEPT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_accept, (int s, void* addr, int addr_size, int* addrlen));
#endif
#ifndef OCALL_SGX_SHUTDOWN_DEFINED__
#define OCALL_SGX_SHUTDOWN_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_shutdown, (int fd, int how));
#endif
#ifndef OCALL_SGX_READ_DEFINED__
#define OCALL_SGX_READ_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_read, (int fd, void* buf, int n));
#endif
#ifndef OCALL_SGX_WRITE_DEFINED__
#define OCALL_SGX_WRITE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_write, (int fd, const void* buf, int n));
#endif
#ifndef OCALL_SGX_CLOSE_DEFINED__
#define OCALL_SGX_CLOSE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_close, (int fd));
#endif
#ifndef OCALL_SGX_GETENV_DEFINED__
#define OCALL_SGX_GETENV_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_getenv, (const char* env, int envlen, char* ret_str, int ret_len));
#endif
#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif
#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif

sgx_status_t ecall_test(sgx_enclave_id_t eid, int* retval, const char* message, size_t message_len);
sgx_status_t ecall_start_tls_server(sgx_enclave_id_t eid, sgx_status_t* retval);
sgx_status_t ecall_main(sgx_enclave_id_t eid, sgx_status_t* retval);
sgx_status_t get_sealed_data_size(sgx_enclave_id_t eid, uint32_t* retval, uint32_t data_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
