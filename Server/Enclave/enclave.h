#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include<stdlib.h>
#include<vector>

sgx_status_t sealing_test(void);
void count();// For easy print

char *strcat(char *a, const char *b);
char *copy_char_p(const char *cp);
int split(char *src, char splitter, char *dst[]);
unsigned char* chr2hex(const unsigned char* digest, size_t hash_len);
const char *randchar();
unsigned char* digest2hex(const char *buf, size_t len);
size_t split(char *src, const char *separator, char **result, size_t result_size);
const char *find_path_name(char **input, const char *owner_id, const char *shared_id, size_t in_size);
void update_path_data(char *file_buf, const char *owner_id, const char *shared_id, const char *digest);

static int create_socket_server(int port);
sgx_status_t ecall_start_tls_server(void);
sgx_status_t ecall_main(void);

#endif /* _ENCLAVE_H_ */