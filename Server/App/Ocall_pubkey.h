#ifndef _O_PUB_H_
#define _O_PUB_H_

#ifndef _SERVER_H_
#include"server.h"
#endif /* _SERVER_H_ */

#include<stdbool.h>
#include<openssl/rsa.h>
#include<openssl/pem.h>
#include<openssl/bio.h>
#include<openssl/err.h>

// bool ocall_WritePublicKeyFile(const char *user_id, RSA *pub_key, size_t len);
// bool ocall_ReadPublicKeyFile(const char *user_id, RSA *pRSA, size_t len);
// bool ocall_ReadPublicKeyBuffer(void* src, RSA *pRSA, size_t len);


sgx_status_t ocall_WritePublicKeyFile(const char *user_id, const char *key_str, size_t len){
  BIO *bio = BIO_new(BIO_s_mem());
  BIO_write(bio, key_str, strlen(key_str));
  RSA *pRSA;
  PEM_read_bio_RSA_PUBKEY(bio, &pRSA, NULL, NULL);
  BIO_free(bio);
  FILE *fp = fopen(user_id, "wb");
  if(fp == NULL){
    printf("Error: Can't Open PublicKeyFile.\n");
    return SGX_ERROR_FILE_BAD_STATUS;
  }
  if(PEM_write_RSAPublicKey(fp, pRSA) == 0){
    printf("Error: Can't Write to PublicKeyFile.\n");
    RSA_free(pRSA);
    return SGX_ERROR_FILE_BAD_STATUS;
  }
  RSA_free(pRSA);
  fclose(fp);
  return SGX_SUCCESS;
}
sgx_status_t ocall_ReadPublicKeyFile(const char* user_id, char *key_str, size_t len){
  char fname[130] = "App/";
  strcat(fname, user_id);
  FILE *fp = fopen(fname, "rb");
  if(fp == NULL){
    printf("Error: Can't Open PublicKeyFile.\n");
    return SGX_ERROR_UNEXPECTED;
  }
  RSA *pRSA = (RSA*)malloc(sizeof(pRSA));
  pRSA = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
  fclose(fp);
  // 以下のようにするとセグフォ
  // PEM_read_RSA_PUBKEY(fp, &pRSA, NULL, NULL)
  if(!pRSA){
    printf("Error: Can't Read PublicKeyFile.\n");
    return SGX_ERROR_UNEXPECTED;
  }
  // RSA_print_fp(stdout, pRSA, 0);// 確認用
  BIO *bio = BIO_new(BIO_s_mem());
  PEM_write_bio_RSA_PUBKEY(bio, pRSA);
  const int key_len = BIO_pending(bio);
  BIO_read(bio, key_str, key_len);
  // strncpy(key_str, "Hello", 6);
  RSA_free(pRSA);
  BIO_free(bio);
  printf("LOG: ocall_ReadPublicKeyFile: key_len: %d\n",key_len);
  return SGX_SUCCESS;
}
bool ocall_ReadPublicKeyBuffer(void* src, RSA *pRSA, size_t len){
  FILE *fp = fmemopen(src, len, "rb");
  if(fp == NULL){
    printf("Error: Can't Open PublicKeyFile.\n");
    return false;
  }
  if(PEM_read_RSA_PUBKEY(fp, &pRSA, NULL, NULL) == NULL){
    printf("Error: Can't Read PublicKeyFile.\n");
    return false;
  }
  fclose(fp);
  return true;
}
sgx_status_t ocall_existsPublicKeyFile(const char *user_id, size_t id_size){
  char fname[130] = "App/";
  strcat(fname, user_id);
  FILE *fp = fopen(fname, "rb");
  if(fp == NULL){
    return SGX_ERROR_FILE_BAD_STATUS;
  }
  fclose(fp);
  return SGX_SUCCESS;
}
sgx_status_t ocall_PublicEncrypt(const char *user_id, const unsigned char *src, unsigned char *dst, size_t len){
  bool ret = ocall_existsPublicKeyFile(user_id, strlen(user_id)+1);
  char *key_str = new char[1024];
  char file[128] = "App/";
  strcat(file, user_id);
  // printf("LOG: filename: %s,%d",file,strlen(file));
  size_t length = get_file_size(file, strlen(file)+1);
  printf("LOG: file_length: %ld\n",length);
  sgx_status_t retval = ocall_ReadPublicKeyFile(user_id, key_str, length);
  if(retval != SGX_SUCCESS){
    printf("ERROR: ocall_ReadPublicKeyFile: \n");
    print_error_message(retval);
    return retval;
  }
  RSA *pRSA = RSA_new();
  BIO *bio = BIO_new(BIO_s_mem());
  BIO_write(bio, key_str, strlen(key_str));
  pRSA = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
  // int rsa_size = RSA_size(pRSA);
  // printf("LOG: rsa size: %d",rsa_size);
  int result = RSA_public_encrypt(len, src, dst, pRSA, RSA_PKCS1_OAEP_PADDING);
  printf("LOG: src ,dst size: %ld, %ld, result: %d\n",strlen((char*)src),strlen((char*)dst), result);
  RSA_free(pRSA);
  BIO_free_all(bio);
  if(result < 0){
    printf("ERROR: ocall_PublicEncrypt: \n");
    return SGX_ERROR_UNEXPECTED;
  }
  return SGX_SUCCESS;
}
#endif /* _PUB_H_ */