#ifndef _E_SEALING_H_
#define _E_SEALING_H_

#ifndef ENCLAVE_T_H_
#include"enclave_t.h"
#endif /* ENCLAVE_T_H_ */
#ifndef _OCALL_WRAPPERS_H_
#include"Ocall_wrappers.h"
#endif /* _OCALL_WRAPPERS_H_ */
#include<cstring>
#include<sgx_tseal.h>

char encrypt_data[BUFSIZ] = "Data to encrypt";
char aad_mac_text[BUFSIZ] = "aad mac text";

uint32_t get_sealed_data_size(uint32_t data_size){
  return sgx_calc_sealed_data_size((uint32_t)strlen(aad_mac_text), data_size);
}

sgx_status_t seal_data(char *encrypt_data, uint8_t* sealed_blob, uint32_t data_size){
  uint32_t sealed_data_size = sgx_calc_sealed_data_size((uint32_t)strlen(aad_mac_text), (uint32_t)strlen(encrypt_data));
  if (sealed_data_size == UINT32_MAX)
    return SGX_ERROR_UNEXPECTED;
  if (sealed_data_size > data_size)
    return SGX_ERROR_INVALID_PARAMETER;

  uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
  if(temp_sealed_buf == NULL)
    return SGX_ERROR_OUT_OF_MEMORY;
  sgx_status_t  err = sgx_seal_data((uint32_t)strlen(aad_mac_text), (const uint8_t *)aad_mac_text, (uint32_t)strlen(encrypt_data), (uint8_t *)encrypt_data, sealed_data_size, (sgx_sealed_data_t *)temp_sealed_buf);
  if (err == SGX_SUCCESS){
    // Copy the sealed data to outside buffer
    memcpy(sealed_blob, temp_sealed_buf, sealed_data_size);
  }

  free(temp_sealed_buf);
  return err;
}

sgx_status_t unseal_data(const uint8_t *sealed_blob, char *decrypt_data, size_t data_size){
    uint32_t mac_text_len = sgx_get_add_mac_txt_len((const sgx_sealed_data_t *)sealed_blob);
    uint32_t decrypt_data_len = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_blob);
    if (mac_text_len == UINT32_MAX || decrypt_data_len == UINT32_MAX)
        return SGX_ERROR_UNEXPECTED;
    if(mac_text_len > data_size || decrypt_data_len > data_size)
        return SGX_ERROR_INVALID_PARAMETER;
    uint8_t *de_mac_text =(uint8_t *)malloc(mac_text_len);
    if(de_mac_text == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;
    if(decrypt_data == NULL){
        free(de_mac_text);
        return SGX_ERROR_OUT_OF_MEMORY;
    }
    sgx_status_t ret = sgx_unseal_data((const sgx_sealed_data_t *)sealed_blob, de_mac_text, &mac_text_len, (uint8_t*)decrypt_data, &decrypt_data_len);
    if (ret != SGX_SUCCESS){
        free(de_mac_text);
        return ret;
    }

    // if (memcmp(de_mac_text, aad_mac_text, strlen(aad_mac_text)) || memcmp(decrypt_data, encrypt_data, strlen(encrypt_data))){
    //     ret = SGX_ERROR_UNEXPECTED;
    // }
    free(de_mac_text);
    return ret;
}

// Read file of 'filename' and unseal the data to 'decrypted_data'
sgx_status_t read_unseal_to_buf(const char* filename, char *decrypted_data, size_t len){
  size_t fsize;
  get_file_size(&fsize, filename, strlen(filename) + 1);
  uint8_t *file_buf = (uint8_t*)malloc(fsize);
  sgx_status_t retval;
  read_file_to_buf(&retval, filename, file_buf, fsize);
  if(retval != SGX_SUCCESS){
    printe("Read the sealed data from %s",filename);
    return retval;
  }
  retval = unseal_data(file_buf, decrypted_data, fsize);
  free(file_buf);
  if(retval != SGX_SUCCESS){
    printe("Unseal the sealed data");
    return retval;
  }
  return SGX_SUCCESS;
}

// Seal the 'encrypt_data' and write to file of 'filename' the data
sgx_status_t seal_write_from_buf(const char* filename, char *encrypt_data, size_t len){
  size_t sealed_size = get_sealed_data_size((uint32_t)strlen((const char*)encrypt_data));
  uint8_t *seal_buf = (uint8_t*)malloc(sealed_size);
  if(seal_data(encrypt_data, (uint8_t*)seal_buf, sealed_size) != SGX_SUCCESS){
    printe("Sealed data");
    return SGX_ERROR_UNEXPECTED;
  }
  sgx_status_t retval;
  write_buf_to_file(&retval, filename, seal_buf, sealed_size, 0);
  free(seal_buf);
  if(retval != SGX_SUCCESS){
    printe("Write data from buf");
    return SGX_ERROR_UNEXPECTED;
  }
  return SGX_SUCCESS;
}
#endif /* _E_SEAL_H_ */
