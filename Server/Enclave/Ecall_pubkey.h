#ifndef _E_PUB_H_
#define _E_PUB_H_

#ifndef ENCLAVE_T_H_
#include"enclave_t.h"
#endif /* ENCLAVE_T_H_ */
#ifndef _ENCLAVE_H_
#include"enclave.h"
#endif /* _ENCLAVE_H_ */
#include"sgx_urts.h"
#include"sgx_tcrypto.h"

#include<stdbool.h>
#include<openssl/rsa.h>
#include<openssl/pem.h>
#include<openssl/bio.h> // for convert to RSA instance from PEM string 
#include<openssl/bn.h> // for member of RSA check
#include<openssl/err.h>

bool readpublickeyfile(const char* user_id, RSA *pRSA){
  char *key_str = new char[512];
  sgx_status_t ret;
  size_t len;
  get_file_size(&len, user_id, strlen(user_id));
  ocall_ReadPublicKeyFile(&ret, user_id, key_str, len);
  if(!ret){
    printe("ReadPublicKeyFile: ");
    return false;
  }
  BIO *bio = BIO_new(BIO_s_mem());
  BIO_write(bio, key_str, strlen(key_str));
  pRSA = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
  printe("%d,%d,%d",pRSA->n,pRSA->q,pRSA->p);
  BIO_free(bio);
  return true;
}
bool writepublickeyfile(const char* user_id, RSA *pRSA, size_t len){
  sgx_status_t retval;
  ocall_existsPublicKeyFile(&retval, user_id, strlen(user_id)+1);
  if(retval == SGX_SUCCESS){
    printe("Public Key File exists");
    return false;
  }
  BIO *bio = BIO_new(BIO_s_mem());
  PEM_write_bio_RSA_PUBKEY(bio, pRSA);
  const int key_len = BIO_pending(bio);
  char *key_str = (char*)malloc(key_len+1);
  BIO_read(bio, key_str, key_len);
  BIO_free(bio);
  ocall_WritePublicKeyFile(&retval, user_id, key_str, key_len);
  free(key_str);
  if(retval != SGX_SUCCESS){
    printe("WritePublicKeyFile: ");
    return false;
  }
  return true;
}
bool test_RSA(RSA *pRSA){
  printf("TEST LOG: ");
  if(!pRSA){printf("RSA is empty.\n");return false;}
  printf("%d",RSA_size(pRSA));
  // printf(" %s", BN_bn2hex(pRSA->n));
  printf("\n");
  return true;
}
bool PublicEncrypt(bool &retb, const char *user_id, const unsigned char *src, unsigned char *dst, size_t len){
  retb = false;
  sgx_status_t retval;
  ocall_existsPublicKeyFile(&retval, user_id, strlen(user_id)+1);
  if(retval != SGX_SUCCESS){
    printe("Public Key File not found");
    return retb;
  }
  char file[128] = "App/";
  strcat(file, user_id);
  size_t length;
  get_file_size(&length, file, strlen(file)+1);
  // printl("file_length: %d",length);
  char *key_str = new char[length];
  ocall_ReadPublicKeyFile(&retval, user_id, key_str, length);
  if(retval != SGX_SUCCESS){
    printe("ReadPublicKeyFile: ");
    print_error_message(retval);
    return retb;
  }
  RSA *pRSA = RSA_new();
  BIO *bio = BIO_new(BIO_s_mem());
  int bio_len = BIO_write(bio, key_str, length);
  // printl("BIO wrote %d",bio_len);
  pRSA = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
  // test_RSA(pRSA);
  int result = RSA_public_encrypt(len, src, dst, pRSA, RSA_PKCS1_OAEP_PADDING);//pRSAが空だと強制終了
  printl("src= %d, dst= %d, result: %d",strlen((char*)src),strlen((char*)dst), result);
  RSA_free(pRSA);
  BIO_free_all(bio);
  if(result < 0){
    printe("PublicEncrypt: ");
    return retb;
  }
  retb = true;
  return retb;
}
#endif /* _E_PUB_H_ */