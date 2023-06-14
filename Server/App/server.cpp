#include <stdio.h>
#include <string.h>

#include <unistd.h>
#include <stdlib.h>


#include <iostream>

#include<time.h>
#include<chrono>

#define MAX_PATH FILENAME_MAX

#include"enclave_u.h"
#include"Ocall_implements.h"
#include<sgx_urts.h>

#ifndef _SERVER_H_
#include"server.h"
#endif /* _SERVER_H_ */
#include"Ocall_sealing.h"
#include"Ocall_pubkey.h"

#include<openssl/rsa.h>
#include<openssl/pem.h>
#include<openssl/err.h>

sgx_enclave_id_t global_eid = 0;

void ocall_print(const char* str){
  std::cout<<"Output from OCALL: "<<std::endl<<str<<std::endl;
}
void uprint(const char *str){
  printf("%s\n", str);
  fflush(stdout);
}

// logging 関連
long get_system_time(){
  using namespace std;
  chrono::system_clock::time_point t_p = chrono::system_clock::now();
  chrono::microseconds epoch_m = chrono::time_point_cast<chrono::microseconds>(t_p).time_since_epoch();
  long epoch_now = chrono::duration_cast<chrono::microseconds>(epoch_m).count();
  return epoch_now;
}
void print_log(long start, long end, size_t len){
  FILE *log_file;
  const char* filename = "20230206.txt";
  log_file = fopen(filename,"a");
  if(log_file ==NULL){
    printf("cannot open %s",filename);
    exit(1);
  }
  fprintf(log_file, "%ld,%ld\n",start,end);
  // printf("test: %ld,%lu\n",start,end);
  std::fclose(log_file);
}

sgx_status_t initialize_enclave(){
  std::string launch_token_path = "launch.token";
  std::string enclave_name = "enclave.signed.so";
  const char* token_path = launch_token_path.c_str();

  sgx_launch_token_t token = {0};
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;

  int updated = 0;

  FILE *fp = fopen(token_path, "rb");

  if(fp == NULL && (fp = fopen(token_path, "wb")) == NULL){
    printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);

  }
  printf("token_path: %s\n", token_path);
  if(fp != NULL){
    size_t read_num  = fread(token, 1, sizeof(sgx_launch_token_t), fp);
    if(read_num != 0 &&read_num != sizeof(sgx_launch_token_t)){
      memset(&token, 0x0, sizeof(sgx_launch_token_t));
      printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
    }
  }

  ret = sgx_create_enclave(enclave_name.c_str(), SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
  if (ret != SGX_SUCCESS) {
    print_error_message(ret);
    if(fp != NULL)fclose(fp);
    return ret;
  }

  if(updated == 0 || fp == NULL){
    if(fp != NULL)fclose(fp);
    return SGX_SUCCESS;
  }

  fp = freopen(token_path, "wb", fp);
  if(fp == NULL)return SGX_SUCCESS;
  size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
  if(write_num != sizeof(sgx_launch_token_t))printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
  fclose(fp);
  return SGX_SUCCESS;
}

bool initialize_files(){
  FILE *fp = fopen("App/data_seal.txt","ab");
  fclose(fp);
  return true;
}
void usgx_exit(int reason){
  printf("usgx_exit: %d\n", reason);
  exit(reason);
}

int SGX_CDECL main(int argc, char* argv[]){
  (void)(argc);
  (void)(argv);
  initialize_files();
  sgx_status_t retval;
  do{
    if (initialize_enclave() != SGX_SUCCESS) {
      printf("Info: Fail initialize enclave...");
      getchar();
      return -1;
    }
    ecall_main(global_eid, &retval);
    sgx_destroy_enclave(global_eid); // enclave 終了
    print_error_message(retval);
    printf("Info: Enclave in closed.\n");
    if(retval == SGX_SUCCESS){
      printf("Info: TLS Server successfully returned.\n");
    }else{
      printf("Info: TLS Server returned with accident.\n");
      printf("%s\n",ERR_error_string(ERR_get_error(), NULL));
      // sleep(5);
      break;
    }
  }while(retval);

  return 0;
}
