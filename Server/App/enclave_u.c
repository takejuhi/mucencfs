#include "enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_test_t {
	int ms_retval;
	const char* ms_message;
	size_t ms_message_len;
} ms_ecall_test_t;

typedef struct ms_ecall_start_tls_server_t {
	sgx_status_t ms_retval;
} ms_ecall_start_tls_server_t;

typedef struct ms_ecall_main_t {
	sgx_status_t ms_retval;
} ms_ecall_main_t;

typedef struct ms_get_sealed_data_size_t {
	uint32_t ms_retval;
	uint32_t ms_data_size;
} ms_get_sealed_data_size_t;

typedef struct ms_ocall_print_t {
	const char* ms_str;
} ms_ocall_print_t;

typedef struct ms_uprint_t {
	const char* ms_str;
} ms_uprint_t;

typedef struct ms_usgx_exit_t {
	int ms_reason;
} ms_usgx_exit_t;

typedef struct ms_print_log_t {
	long int ms_start;
	long int ms_end;
	size_t ms_len;
} ms_print_log_t;

typedef struct ms_print_error_message_t {
	sgx_status_t ms_ret;
} ms_print_error_message_t;

typedef struct ms_get_system_time_t {
	long int ms_retval;
} ms_get_system_time_t;

typedef struct ms_read_file_to_buf_t {
	sgx_status_t ms_retval;
	const char* ms_filename;
	uint8_t* ms_buf;
	size_t ms_bsize;
} ms_read_file_to_buf_t;

typedef struct ms_write_buf_to_file_t {
	sgx_status_t ms_retval;
	const char* ms_filename;
	const uint8_t* ms_buf;
	size_t ms_bsize;
	long int ms_offset;
} ms_write_buf_to_file_t;

typedef struct ms_get_file_size_t {
	size_t ms_retval;
	const char* ms_filename;
	size_t ms_len;
} ms_get_file_size_t;

typedef struct ms_ocall_WritePublicKeyFile_t {
	sgx_status_t ms_retval;
	const char* ms_user_id;
	const char* ms_key_str;
	size_t ms_len;
} ms_ocall_WritePublicKeyFile_t;

typedef struct ms_ocall_ReadPublicKeyFile_t {
	sgx_status_t ms_retval;
	const char* ms_user_id;
	char* ms_key_str;
	size_t ms_len;
} ms_ocall_ReadPublicKeyFile_t;

typedef struct ms_ocall_existsPublicKeyFile_t {
	sgx_status_t ms_retval;
	const char* ms_user_id;
	size_t ms_id_size;
} ms_ocall_existsPublicKeyFile_t;

typedef struct ms_ocall_sgx_clock_t {
	long int ms_retval;
} ms_ocall_sgx_clock_t;

typedef struct ms_ocall_sgx_time_t {
	time_t ms_retval;
	time_t* ms_timep;
	int ms_t_len;
} ms_ocall_sgx_time_t;

typedef struct ms_ocall_sgx_localtime_t {
	struct tm* ms_retval;
	const time_t* ms_timep;
	int ms_t_len;
} ms_ocall_sgx_localtime_t;

typedef struct ms_ocall_sgx_gmtime_r_t {
	struct tm* ms_retval;
	const time_t* ms_timep;
	int ms_t_len;
	struct tm* ms_tmp;
	int ms_tmp_len;
} ms_ocall_sgx_gmtime_r_t;

typedef struct ms_ocall_sgx_gettimeofday_t {
	int ms_retval;
	void* ms_tv;
	int ms_tv_size;
} ms_ocall_sgx_gettimeofday_t;

typedef struct ms_ocall_sgx_getsockopt_t {
	int ms_retval;
	int ms_s;
	int ms_level;
	int ms_optname;
	char* ms_optval;
	int ms_optval_len;
	int* ms_optlen;
} ms_ocall_sgx_getsockopt_t;

typedef struct ms_ocall_sgx_setsockopt_t {
	int ms_retval;
	int ms_s;
	int ms_level;
	int ms_optname;
	const void* ms_optval;
	int ms_optlen;
} ms_ocall_sgx_setsockopt_t;

typedef struct ms_ocall_sgx_socket_t {
	int ms_retval;
	int ms_af;
	int ms_type;
	int ms_protocol;
} ms_ocall_sgx_socket_t;

typedef struct ms_ocall_sgx_listen_t {
	int ms_retval;
	int ms_s;
	int ms_backlog;
} ms_ocall_sgx_listen_t;

typedef struct ms_ocall_sgx_bind_t {
	int ms_retval;
	int ms_s;
	const void* ms_addr;
	int ms_addr_size;
} ms_ocall_sgx_bind_t;

typedef struct ms_ocall_sgx_connect_t {
	int ms_retval;
	int ms_s;
	const void* ms_addr;
	int ms_addrlen;
} ms_ocall_sgx_connect_t;

typedef struct ms_ocall_sgx_accept_t {
	int ms_retval;
	int ms_s;
	void* ms_addr;
	int ms_addr_size;
	int* ms_addrlen;
} ms_ocall_sgx_accept_t;

typedef struct ms_ocall_sgx_shutdown_t {
	int ms_retval;
	int ms_fd;
	int ms_how;
} ms_ocall_sgx_shutdown_t;

typedef struct ms_ocall_sgx_read_t {
	int ms_retval;
	int ms_fd;
	void* ms_buf;
	int ms_n;
} ms_ocall_sgx_read_t;

typedef struct ms_ocall_sgx_write_t {
	int ms_retval;
	int ms_fd;
	const void* ms_buf;
	int ms_n;
} ms_ocall_sgx_write_t;

typedef struct ms_ocall_sgx_close_t {
	int ms_retval;
	int ms_fd;
} ms_ocall_sgx_close_t;

typedef struct ms_ocall_sgx_getenv_t {
	int ms_retval;
	const char* ms_env;
	int ms_envlen;
	char* ms_ret_str;
	int ms_ret_len;
} ms_ocall_sgx_getenv_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL enclave_ocall_print(void* pms)
{
	ms_ocall_print_t* ms = SGX_CAST(ms_ocall_print_t*, pms);
	ocall_print(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_uprint(void* pms)
{
	ms_uprint_t* ms = SGX_CAST(ms_uprint_t*, pms);
	uprint(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_usgx_exit(void* pms)
{
	ms_usgx_exit_t* ms = SGX_CAST(ms_usgx_exit_t*, pms);
	usgx_exit(ms->ms_reason);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_print_log(void* pms)
{
	ms_print_log_t* ms = SGX_CAST(ms_print_log_t*, pms);
	print_log(ms->ms_start, ms->ms_end, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_print_error_message(void* pms)
{
	ms_print_error_message_t* ms = SGX_CAST(ms_print_error_message_t*, pms);
	print_error_message(ms->ms_ret);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_get_system_time(void* pms)
{
	ms_get_system_time_t* ms = SGX_CAST(ms_get_system_time_t*, pms);
	ms->ms_retval = get_system_time();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_read_file_to_buf(void* pms)
{
	ms_read_file_to_buf_t* ms = SGX_CAST(ms_read_file_to_buf_t*, pms);
	ms->ms_retval = read_file_to_buf(ms->ms_filename, ms->ms_buf, ms->ms_bsize);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_write_buf_to_file(void* pms)
{
	ms_write_buf_to_file_t* ms = SGX_CAST(ms_write_buf_to_file_t*, pms);
	ms->ms_retval = write_buf_to_file(ms->ms_filename, ms->ms_buf, ms->ms_bsize, ms->ms_offset);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_get_file_size(void* pms)
{
	ms_get_file_size_t* ms = SGX_CAST(ms_get_file_size_t*, pms);
	ms->ms_retval = get_file_size(ms->ms_filename, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_WritePublicKeyFile(void* pms)
{
	ms_ocall_WritePublicKeyFile_t* ms = SGX_CAST(ms_ocall_WritePublicKeyFile_t*, pms);
	ms->ms_retval = ocall_WritePublicKeyFile(ms->ms_user_id, ms->ms_key_str, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_ReadPublicKeyFile(void* pms)
{
	ms_ocall_ReadPublicKeyFile_t* ms = SGX_CAST(ms_ocall_ReadPublicKeyFile_t*, pms);
	ms->ms_retval = ocall_ReadPublicKeyFile(ms->ms_user_id, ms->ms_key_str, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_existsPublicKeyFile(void* pms)
{
	ms_ocall_existsPublicKeyFile_t* ms = SGX_CAST(ms_ocall_existsPublicKeyFile_t*, pms);
	ms->ms_retval = ocall_existsPublicKeyFile(ms->ms_user_id, ms->ms_id_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_sgx_clock(void* pms)
{
	ms_ocall_sgx_clock_t* ms = SGX_CAST(ms_ocall_sgx_clock_t*, pms);
	ms->ms_retval = ocall_sgx_clock();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_sgx_time(void* pms)
{
	ms_ocall_sgx_time_t* ms = SGX_CAST(ms_ocall_sgx_time_t*, pms);
	ms->ms_retval = ocall_sgx_time(ms->ms_timep, ms->ms_t_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_sgx_localtime(void* pms)
{
	ms_ocall_sgx_localtime_t* ms = SGX_CAST(ms_ocall_sgx_localtime_t*, pms);
	ms->ms_retval = ocall_sgx_localtime(ms->ms_timep, ms->ms_t_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_sgx_gmtime_r(void* pms)
{
	ms_ocall_sgx_gmtime_r_t* ms = SGX_CAST(ms_ocall_sgx_gmtime_r_t*, pms);
	ms->ms_retval = ocall_sgx_gmtime_r(ms->ms_timep, ms->ms_t_len, ms->ms_tmp, ms->ms_tmp_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_sgx_gettimeofday(void* pms)
{
	ms_ocall_sgx_gettimeofday_t* ms = SGX_CAST(ms_ocall_sgx_gettimeofday_t*, pms);
	ms->ms_retval = ocall_sgx_gettimeofday(ms->ms_tv, ms->ms_tv_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_sgx_getsockopt(void* pms)
{
	ms_ocall_sgx_getsockopt_t* ms = SGX_CAST(ms_ocall_sgx_getsockopt_t*, pms);
	ms->ms_retval = ocall_sgx_getsockopt(ms->ms_s, ms->ms_level, ms->ms_optname, ms->ms_optval, ms->ms_optval_len, ms->ms_optlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_sgx_setsockopt(void* pms)
{
	ms_ocall_sgx_setsockopt_t* ms = SGX_CAST(ms_ocall_sgx_setsockopt_t*, pms);
	ms->ms_retval = ocall_sgx_setsockopt(ms->ms_s, ms->ms_level, ms->ms_optname, ms->ms_optval, ms->ms_optlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_sgx_socket(void* pms)
{
	ms_ocall_sgx_socket_t* ms = SGX_CAST(ms_ocall_sgx_socket_t*, pms);
	ms->ms_retval = ocall_sgx_socket(ms->ms_af, ms->ms_type, ms->ms_protocol);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_sgx_listen(void* pms)
{
	ms_ocall_sgx_listen_t* ms = SGX_CAST(ms_ocall_sgx_listen_t*, pms);
	ms->ms_retval = ocall_sgx_listen(ms->ms_s, ms->ms_backlog);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_sgx_bind(void* pms)
{
	ms_ocall_sgx_bind_t* ms = SGX_CAST(ms_ocall_sgx_bind_t*, pms);
	ms->ms_retval = ocall_sgx_bind(ms->ms_s, ms->ms_addr, ms->ms_addr_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_sgx_connect(void* pms)
{
	ms_ocall_sgx_connect_t* ms = SGX_CAST(ms_ocall_sgx_connect_t*, pms);
	ms->ms_retval = ocall_sgx_connect(ms->ms_s, ms->ms_addr, ms->ms_addrlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_sgx_accept(void* pms)
{
	ms_ocall_sgx_accept_t* ms = SGX_CAST(ms_ocall_sgx_accept_t*, pms);
	ms->ms_retval = ocall_sgx_accept(ms->ms_s, ms->ms_addr, ms->ms_addr_size, ms->ms_addrlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_sgx_shutdown(void* pms)
{
	ms_ocall_sgx_shutdown_t* ms = SGX_CAST(ms_ocall_sgx_shutdown_t*, pms);
	ms->ms_retval = ocall_sgx_shutdown(ms->ms_fd, ms->ms_how);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_sgx_read(void* pms)
{
	ms_ocall_sgx_read_t* ms = SGX_CAST(ms_ocall_sgx_read_t*, pms);
	ms->ms_retval = ocall_sgx_read(ms->ms_fd, ms->ms_buf, ms->ms_n);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_sgx_write(void* pms)
{
	ms_ocall_sgx_write_t* ms = SGX_CAST(ms_ocall_sgx_write_t*, pms);
	ms->ms_retval = ocall_sgx_write(ms->ms_fd, ms->ms_buf, ms->ms_n);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_sgx_close(void* pms)
{
	ms_ocall_sgx_close_t* ms = SGX_CAST(ms_ocall_sgx_close_t*, pms);
	ms->ms_retval = ocall_sgx_close(ms->ms_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_sgx_getenv(void* pms)
{
	ms_ocall_sgx_getenv_t* ms = SGX_CAST(ms_ocall_sgx_getenv_t*, pms);
	ms->ms_retval = ocall_sgx_getenv(ms->ms_env, ms->ms_envlen, ms->ms_ret_str, ms->ms_ret_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[35];
} ocall_table_enclave = {
	35,
	{
		(void*)enclave_ocall_print,
		(void*)enclave_uprint,
		(void*)enclave_usgx_exit,
		(void*)enclave_print_log,
		(void*)enclave_print_error_message,
		(void*)enclave_get_system_time,
		(void*)enclave_read_file_to_buf,
		(void*)enclave_write_buf_to_file,
		(void*)enclave_get_file_size,
		(void*)enclave_ocall_WritePublicKeyFile,
		(void*)enclave_ocall_ReadPublicKeyFile,
		(void*)enclave_ocall_existsPublicKeyFile,
		(void*)enclave_ocall_sgx_clock,
		(void*)enclave_ocall_sgx_time,
		(void*)enclave_ocall_sgx_localtime,
		(void*)enclave_ocall_sgx_gmtime_r,
		(void*)enclave_ocall_sgx_gettimeofday,
		(void*)enclave_ocall_sgx_getsockopt,
		(void*)enclave_ocall_sgx_setsockopt,
		(void*)enclave_ocall_sgx_socket,
		(void*)enclave_ocall_sgx_listen,
		(void*)enclave_ocall_sgx_bind,
		(void*)enclave_ocall_sgx_connect,
		(void*)enclave_ocall_sgx_accept,
		(void*)enclave_ocall_sgx_shutdown,
		(void*)enclave_ocall_sgx_read,
		(void*)enclave_ocall_sgx_write,
		(void*)enclave_ocall_sgx_close,
		(void*)enclave_ocall_sgx_getenv,
		(void*)enclave_ocall_print_string,
		(void*)enclave_sgx_oc_cpuidex,
		(void*)enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t ecall_test(sgx_enclave_id_t eid, int* retval, const char* message, size_t message_len)
{
	sgx_status_t status;
	ms_ecall_test_t ms;
	ms.ms_message = message;
	ms.ms_message_len = message_len;
	status = sgx_ecall(eid, 0, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_start_tls_server(sgx_enclave_id_t eid, sgx_status_t* retval)
{
	sgx_status_t status;
	ms_ecall_start_tls_server_t ms;
	status = sgx_ecall(eid, 1, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_main(sgx_enclave_id_t eid, sgx_status_t* retval)
{
	sgx_status_t status;
	ms_ecall_main_t ms;
	status = sgx_ecall(eid, 2, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t get_sealed_data_size(sgx_enclave_id_t eid, uint32_t* retval, uint32_t data_size)
{
	sgx_status_t status;
	ms_get_sealed_data_size_t ms;
	ms.ms_data_size = data_size;
	status = sgx_ecall(eid, 3, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

