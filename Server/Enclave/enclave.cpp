#include"enclave_t.h"
#include"Ocall_wrappers.h"

#include<sgx_trts.h>
#include"sgx_tseal.h"
#include<stdio.h>
#include<string>

#include<openssl/evp.h>
#include<openssl/ssl.h>
#include<openssl/x509.h>
#include<openssl/pem.h>
#include<openssl/rsa.h>
#include<openssl/err.h>

#include"enclave.h"
#include"Ecall_sealing.h"
#include"Ecall_pubkey.h"

#ifndef HASH_COUNT
#define HASH_COUNT 1
#endif /* HASH_COUNT */
#define SEALED_FILE "App/data_seal.txt"

int EVP_CALLED = 0;
int ecall_test(const char *message, size_t message_len){
  ocall_print(message);
  // TLSv1_2_method();
  return 31337;
}
sgx_status_t sealing_test(){
  const char sealed_file[18] = "App/data_seal.txt";
  // initialize path_name data
  // char cont[] = "someone,cishosei,4A33E01C5FC55BFD8803BDA7BD788DE7\nsomeone,someone,7F8944F57738B48B62E685F23055D6EB";
  // size_t s_len = strlen(cont);
  // if(seal_write_from_buf(sealed_file,cont,s_len) != SGX_SUCCESS){
  //   printe("Seal Test");
  //   return SGX_ERROR_UNEXPECTED;
  // }
  // printl("Sealing SUCCESS");
  // check path_name data
  size_t fsize;
  get_file_size(&fsize, sealed_file, strlen(sealed_file) + 1);
  char *file_buf = (char*)malloc(fsize);
  if(read_unseal_to_buf(sealed_file,file_buf, fsize) != SGX_SUCCESS){
    printe("Unseal Test");
    return SGX_ERROR_UNEXPECTED;
  }
  printl("filebuf: %d: %d \n%s",strlen(file_buf),fsize,file_buf);
  free(file_buf);
  return SGX_SUCCESS;
}
int TEST = 0;
void count(){
  printf("( * _ * ) %d ( * _ * )\n",TEST);
  TEST++;
}
//没関数
std::vector<std::string> split(std::string str, const char splitter){
  int first = 0;
  int last = str.find_first_of(splitter);
  std::vector<std::string> out;
  while(first < str.size()){
    // std::substr()はコンパイル失敗
    std::string subStr(str, first, last - first);
    printl("%s",subStr.c_str());
    // forming reference to reference typeとかでpush_backはどうやってもできない(コンパイルエラー) 
    // out.push_back(subStr);
    first = last + 1;
    last = str.find_first_of(splitter, first);
    if(last == std::string::npos){
      last = str.size();
    }
    // printl("%d,%d",start,last);
  }
  return out;
}

#ifndef SSL_PORT
#define SSL_PORT 4433
#endif
#ifndef CERT_PATH
#define CERT_PATH "server.cert"
#endif
#ifndef MAX_SSL_CTX
#define MAX_SSL_CTX 2
#endif
#ifndef MAX_SSL
#define MAX_SSL 2
#endif
SSL_CTX* CTX_TABLE[MAX_SSL_CTX];
SSL* SSL_TABLE[MAX_SSL];

static void eSSL_init(void){
  OpenSSL_add_ssl_algorithms();
  SSL_load_error_strings();
}
static void eSSL_cleanup(void){
  EVP_cleanup();
}
static long AddCTX(SSL_CTX* ctx){
  long i;
  for (i = 0; i < MAX_SSL_CTX; i++) {
    if (CTX_TABLE[i] == NULL) {
      CTX_TABLE[i] = ctx;
      return i;
    }
  }
  return -1;
}
static long AddSSL(SSL* ssl){
  long i;
  for (i = 0; i < MAX_SSL; i++) {
    if (SSL_TABLE[i] == NULL) {
      SSL_TABLE[i] = ssl;
      return i;
    }
  }
  return -1;
}
static SSL_CTX* GetCTX(long id){
  if (id >= MAX_SSL_CTX || id < 0)return NULL;
  return CTX_TABLE[id];
}
static SSL* GetSSL(long id){
  if (id >= MAX_SSL || id < 0)return NULL;
  return SSL_TABLE[id];
}
static void RemoveCTX(long id){
  if (id >= MAX_SSL_CTX || id < 0)return;
  SSL_CTX_free(CTX_TABLE[id]);
  CTX_TABLE[id] = NULL;
}
static void RemoveSSL(long id){
  if (id >= MAX_SSL || id < 0)return;
  SSL_free(SSL_TABLE[id]);
  SSL_TABLE[id] = NULL;
}

long eSSL_CTX_new(void){
  const SSL_METHOD *method = TLSv1_2_server_method();
  long id = -1;
  SSL_CTX *ctx = SSL_CTX_new(method);
  if(!ctx){
    printe("Unable to create SSL context");
    exit(EXIT_FAILURE);
  }else if(ctx != NULL){id = AddCTX(ctx);}
  return id;
}
long eSSL_new(long id){
  SSL_CTX *ctx;
  SSL *ssl;
  long ret = -1;
  ctx = GetCTX(id);
  if(ctx == NULL)return -1;
  ssl = SSL_new(ctx);
  if(ssl != NULL)ret = AddSSL(ssl);
  return ret;
}
int eSSL_set_fd(long sslid, int fd){
  SSL *ssl = GetSSL(sslid);
  if(ssl == NULL)return -1;
  return SSL_set_fd(ssl, fd);
}
int eSSL_write(long sslId, const void* in, int sz){
  SSL* ssl = GetSSL(sslId);
  if (ssl == NULL)return -1;
  return SSL_write(ssl, in, sz);
}
int eSSL_get_error(long sslId, int ret){
  SSL* ssl = GetSSL(sslId);
  if (ssl == NULL)return -1;
  return SSL_get_error(ssl, ret);
}
int eSSL_read(long sslId, void* data, int sz){
  SSL* ssl = GetSSL(sslId);
  if (ssl == NULL)return -1;
  return SSL_read(ssl, data, sz);
}
void eSSL_free(long sslId){
  RemoveSSL(sslId);
}
void eSSL_CTX_free(long id){
  RemoveCTX(id);
}
void eSSL_Cleanup(void){
  long id;
  for (id = 0; id < MAX_SSL; id++)
    RemoveSSL(id);
  for (id = 0; id < MAX_SSL_CTX; id++)
    RemoveCTX(id);
}

static EVP_PKEY *generatePrivateKey(){
  EVP_PKEY *pkey = NULL;
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  EVP_PKEY_keygen_init(pctx);
  EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048);
  EVP_PKEY_keygen(pctx, &pkey);
  return pkey;
}
static X509 *generateCertificate(EVP_PKEY *pkey){
  X509 *x509 = X509_new();
  X509_set_version(x509, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(x509), 0);
  X509_gmtime_adj(X509_get_notBefore(x509), 0);
  X509_gmtime_adj(X509_get_notAfter(x509), (long)60*60*24*365);
  X509_set_pubkey(x509, pkey);

  X509_NAME *name = X509_get_subject_name(x509);
  X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)"JP", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)"cis_hosei", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)"localhost", -1, -1, 0);
  X509_set_issuer_name(x509, name);
  X509_sign(x509, pkey, EVP_sha256());
  return x509;
}
static int password_cb(char *buf, int size, int rwflag, void *password){
  strncpy(buf, (char *)(password), size);
  buf[size - 1] = '\0';
  return strlen(buf);
}
static void configure_context(SSL_CTX *ctx){
  EVP_PKEY *pkey = generatePrivateKey();
  X509 *x509 = generateCertificate(pkey);

  SSL_CTX_use_certificate(ctx, x509);
  SSL_CTX_set_default_passwd_cb(ctx, password_cb);
  SSL_CTX_use_PrivateKey(ctx, pkey);

  RSA *rsa=RSA_generate_key(512, RSA_F4, NULL, NULL);
  SSL_CTX_set_tmp_rsa(ctx, rsa);
  RSA_free(rsa);

  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);
}

static int create_socket_server(int port){
  int s, optval = 1;
  struct sockaddr_in addr;

  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);

  s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) {
    printe("sgx_socket");
    exit(EXIT_FAILURE);
  }
  if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval, sizeof(int)) < 0) {
    printe("sgx_setsockopt");
    exit(EXIT_FAILURE);
  }
  if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    printe("sgx_bind");
    exit(EXIT_FAILURE);
  }
  if (listen(s, 128) < 0) {
    printe("sgx_listen");
    exit(EXIT_FAILURE);
  }
  return s;
}

sgx_status_t ecall_start_tls_server(void){
  int sock, ret;
  SSL_CTX *ctx;
  long ctx_id, ssl_id;
  printl("OPENSSL Version = %s", SSLeay_version(SSLEAY_VERSION));
  eSSL_init();
  ctx_id = eSSL_CTX_new();
  ctx = GetCTX(ctx_id);
  configure_context(ctx);
  sock = create_socket_server(4433);
  if(sock < 0) {
    printe("create_socket_client: %d", sock);
    exit(EXIT_FAILURE);
  }

  /* Handle SSL/TLS connections */
  while(1) {
    struct sockaddr_in addr;
    int len = sizeof(addr);
    SSL *cli;
    long start, end;
    printl("Wait for new connection...");
    int client = accept(sock, (struct sockaddr*)&addr, &len);
    get_system_time(&start);
    if (client < 0) {
      printe("Unable to accept");
      exit(EXIT_FAILURE);
    }
    ssl_id = eSSL_new(ctx_id);
    cli = GetSSL(ssl_id);
    SSL_set_fd(cli, client);
    ret = SSL_accept(cli);
    if (ret <= 0) {
      printe("SSL_accept: reason: %d",(SSL_get_error(cli, ret)));
      printe(ERR_reason_error_string(ERR_get_error()));
      continue;
    }

    // printl("ciphersuit: %s", SSL_get_current_cipher(cli)->name);
    char read_buf[512];
    memset(read_buf, '\0', sizeof(read_buf));

    int r = 0, w = 0;
    /* Receive buffer from TLS server */
    r = SSL_read(cli, read_buf, sizeof(read_buf));
    printl("read_buf: length = %d : %s", r, read_buf);

    // Parse Request
    char *request[3] = {'\0', '\0', '\0', '\0'};
    size_t request_size;
    request_size = split(read_buf, ',', request);

    unsigned char *write_buf = (unsigned char*)malloc(257);
    memset(write_buf, '\0', sizeof(write_buf));
    if(strncmp(request[0],"pathname", 9) == 0){
      // Parse File Data
      size_t fsize, cont_size;
      get_file_size(&fsize, SEALED_FILE, strlen(SEALED_FILE) + 1);
      char *file_buf = (char*)malloc(fsize);
      memset(file_buf, '\0', fsize);
      if(read_unseal_to_buf(SEALED_FILE,file_buf, fsize) != SGX_SUCCESS){
        printe("Unseal");
        eSSL_free(ssl_id);
        sgx_close(client);
        continue;
      }
      char *file_cont[1024];
      cont_size = split(file_buf, '\n', file_cont);

      unsigned char *path_name;
      path_name = (unsigned char*)find_path_name(file_cont, request[1], request[2], cont_size);
      if(path_name != NULL){
        printl("requested data is %s", path_name);
      }else{
        printe("requested data not found.");
        char *chara = (char*)malloc(sizeof(read_buf));
        memset(chara, '\0', sizeof(read_buf));
        strcat(chara, request[1]);
        strcat(chara, request[2]);
        path_name = digest2hex(chara, 32);
        free(chara);
        // save file data
        update_path_data(file_buf, request[1], request[2], (char*)path_name);
      }
      free(file_buf);
      len = strlen((char*)path_name);
      bool retb;
      int requester = 1;
      if(strcmp(request[3], "2") == 0)requester = 2;
      PublicEncrypt(retb, request[requester], path_name, write_buf, len);
      if(!retb){
        eSSL_free(ssl_id);
        sgx_close(client);
        continue;
      }
    }else if(strncmp(request[0], "publickey", 10) == 0){
      strcat((char*)write_buf, "Under construction");
      printl("0");
    }
    
    // response
    w = SSL_write(cli, write_buf, 256);
    printl("written_buf: length = %d ", w);
    free(write_buf);
    
    get_system_time(&end);
    printl("start: %ld, end: %ld, ellapsed time %ld[ms]", start, end, end-start);
    print_log(start,end,sizeof(long));
    printl("Close SSL/TLS client");
    eSSL_free(ssl_id);
    sgx_close(client);
    if(EVP_CALLED > 5000){
      printl("EVP_MD called %d times.",EVP_CALLED);
      break;
    }
  }
  sgx_close(sock);
  eSSL_CTX_free(ctx_id);
  eSSL_cleanup();
  return SGX_SUCCESS;
}
sgx_status_t ecall_main(void){
  uprint("Init");
  sgx_status_t retval;
  retval = sealing_test();
  retval = ecall_start_tls_server();
  if(retval != SGX_SUCCESS){
    printe(ERR_error_string(ERR_get_error(), NULL));
  }
  return retval;
}
char *strcat(char *a, const char *b){
  while(*a++); a--; while(*a++=*b++);
  return a;
}
char *copy_char_p(const char *cp){
  int i;
  for(i=0;cp[i]!='\0';++i);
  char *c = (char*)malloc(sizeof(char)*(i+1));
  char *result = c;
  while(*cp != '\0'){
    *c=*cp;c++;cp++;
  }
  *c = '\0';
  return result;
}
int split(char *src, char splitter, char *dst[]){
  int count = 0;
  char *_src = copy_char_p(src);
  for(;;){
    while(*_src == splitter)_src++;
    if(*_src == '\0')break;
    dst[count++] = _src;
    while(*_src && *_src != splitter)_src++;
    if(*_src == '\0')break;
    *_src++ = '\0';
  }
  return count;
}
// make a char list into 'result' splitted by 'separator' from 'src'
size_t split(char *src, const char *separator, char **result, size_t result_size){
  size_t s_len = strlen(src);
  size_t start = 0, end = 0, i = 0;
  char *src_copy = (char*)malloc(s_len+1);
  memset(src_copy, '\0', s_len);
  strcat(src_copy,src);
  do{
    end = start + strcspn(&src_copy[start], separator);
    
    src_copy[end] = '\0';
    if(i >= result_size)return NULL;
    result[i] = &src_copy[start];
    ++i;
    start = end + 1;
  }while(start <= s_len);
  // free(src_copy);
  return i;
}

unsigned char* chr2hex(const unsigned char* digest, size_t hash_len){
  size_t final_len = hash_len / 2;
  unsigned char* chrs = (unsigned char*)malloc((final_len+1)*sizeof(*chrs));
  int j;
  for(j=0;j<final_len;j++){
    chrs[2*j] = (digest[j]>>4)+48;
    chrs[2*j+1] = (digest[j]&15)+48;
    if (chrs[2*j]>57)chrs[2*j]+=7;
    if (chrs[2*j+1]>57)chrs[2*j+1]+=7;
  }
  chrs[2*j] = '\0';
  return chrs;
}
const char *randchar(){
  return "Beef or Chicken";
}
unsigned char* digest2hex(const char *buf, size_t len){
  unsigned int msg_size = NULL;
  unsigned char digest[len] = {0};
  int j;
  const char* pepper = randchar();
  unsigned char *msg = (unsigned char*)malloc(128);// = (unsigned char*)buf;
  memset(msg, '\0', sizeof(msg));
  strcat((char*)msg, buf);
  strcat((char*)msg, pepper);
  EVP_MD_CTX ctx;
  for(j=0;j<HASH_COUNT;j++){
    EVP_MD_CTX_init(&ctx);
    EVP_DigestInit_ex(&ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(&ctx, msg, len);
    EVP_DigestFinal_ex(&ctx, digest, &msg_size);
    if(!j)free(msg);
    msg = digest;
    EVP_CALLED += 1;
    EVP_MD_CTX_cleanup(&ctx);
  }
  unsigned char *result = chr2hex(msg, len);
  printl("calcurate end: %s", result);
  return result;
}

const char *find_path_name(char **input, const char *owner_id, const char *shared_id, size_t in_size){
  if(!owner_id || !shared_id || !in_size)return NULL;
  for(int i=0; i< in_size; i++){
    char *temp_buf = (char*)malloc(strlen(input[0]));
    memset(temp_buf, '\0', strlen(input[0]));
    strcat(temp_buf, input[i]);
    char *temp_result[3];
    size_t result_size;
    result_size = split(temp_buf, ',', temp_result);
    if(result_size != 3)return NULL;
    if((strcmp(temp_result[0], owner_id) == 0) && (strcmp(temp_result[1], shared_id) == 0)){
      return temp_result[2];
    }
    free(temp_buf);
  }
  return NULL;
}
void update_path_data(char *file_buf, const char *owner_id, const char *shared_id, const char *digest){
    char *data_buf = (char*)malloc(strlen(file_buf)+162);
    memset(data_buf, '\0', strlen(file_buf)+162);
    strcat(data_buf, file_buf);
    strcat(data_buf, "\n");
    strcat(data_buf, owner_id);
    strcat(data_buf, ",");
    strcat(data_buf, shared_id);
    strcat(data_buf, ",");
    strcat(data_buf, digest);
    sgx_status_t retval = seal_write_from_buf(SEALED_FILE, data_buf,strlen(data_buf));
    free(data_buf);
    if(retval != SGX_SUCCESS){
      printe("Save data");
      print_error_message(retval);
      return;
    }
    printl("data updated:\n%s: %s: %s",owner_id, shared_id, digest);
}
