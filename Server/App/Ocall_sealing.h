#ifndef _O_SEAL_H_
#define _O_SEAL_H_

#ifndef _SERVER_H_
#include"server.h"
#endif /* _SERVER_H_ */
#include<fstream>

#define SEALED_DATA_FILE "data_blob.txt"

size_t get_file_size(const char *filename, size_t len){
  std::ifstream ifs(filename, std::ios::in | std::ios::binary);
  if (!ifs.good())
  {
    std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
    return -1;
  }
  ifs.seekg(0, std::ios::end);
  size_t size = (size_t)ifs.tellg();
  return size;
}

sgx_status_t read_file_to_buf(const char *filename, uint8_t *buf, size_t bsize){
  std::ifstream ifs(filename, std::ios::binary | std::ios::in);
  if (!ifs.good()){
    std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
    return SGX_ERROR_FILE_BAD_STATUS;
  }
  ifs.read(reinterpret_cast<char *> (buf), bsize);
  if (ifs.fail()){
    std::cout << "Failed to read the file \"" << filename << "\"" << std::endl;
    return SGX_ERROR_FILE_BAD_STATUS;
  }
  return SGX_SUCCESS;
}

sgx_status_t write_buf_to_file(const char *filename, const uint8_t *buf, size_t bsize, long offset){
  std::ofstream ofs(filename, std::ios::binary | std::ios::out);
  if (!ofs.good())    {
    std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
    return SGX_ERROR_FILE_BAD_STATUS;
  }
  ofs.seekp(offset, std::ios::beg);
  ofs.write(reinterpret_cast<const char*>(buf), bsize);
  if (ofs.fail()){
    std::cout << "Failed to write the file \"" << filename << "\"" << std::endl;
    return SGX_ERROR_FILE_BAD_STATUS;
  }
  return SGX_SUCCESS;
}


// 4 test
// static bool seal_and_save_data()
// {
//     // Get the sealed data size
//     uint32_t sealed_data_size = 0;
//     sgx_status_t ret = get_sealed_data_size(global_eid, &sealed_data_size, sealed_data_size);
//     printf("%d\n",0);
//     if (ret != SGX_SUCCESS)
//     {
//         print_error_message(ret);
//     printf("%d\n",0);
//         return false;
//     }
//     else if(sealed_data_size == UINT32_MAX)
//     {
//         return false;
//     }
//     uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
//     if(temp_sealed_buf == NULL)
//     {
//         std::cout << "Out of memory" << std::endl;
//         return false;
//     }
//     sgx_status_t retval;
//     ret = seal_data(global_eid, &retval, (char*)temp_sealed_buf, sealed_data_size);
//     if (ret != SGX_SUCCESS)
//     {
//         print_error_message(ret);
//         free(temp_sealed_buf);
//         return false;
//     }
//     else if( retval != SGX_SUCCESS)
//     {
//         print_error_message(retval);
//         free(temp_sealed_buf);
//         return false;
//     }

//     // Save the sealed blob
//     if (write_buf_to_file(SEALED_DATA_FILE, temp_sealed_buf, sealed_data_size, 0) == false)
//     {
//         std::cout << "Failed to save the sealed data blob to \"" << SEALED_DATA_FILE << "\"" << std::endl;
//         free(temp_sealed_buf);
//         return false;
//     }

//     free(temp_sealed_buf);

//     std::cout << "Sealing data succeeded." << std::endl;
//     return true;

// }

// static bool read_and_unseal_data()
// {
//     // Read the sealed blob from the file
//     size_t fsize = get_file_size(SEALED_DATA_FILE);
//     if (fsize == (size_t)-1)
//     {
//         std::cout << "Failed to get the file size of \"" << SEALED_DATA_FILE << "\"" << std::endl;
//         return false;
//     }
//     uint8_t *temp_buf = (uint8_t *)malloc(fsize);
//     if(temp_buf == NULL)
//     {
//         std::cout << "Out of memory" << std::endl;
//         return false;
//     }
//     if (read_file_to_buf(SEALED_DATA_FILE, temp_buf, fsize) == false)
//     {
//         std::cout << "Failed to read the sealed data blob from \"" << SEALED_DATA_FILE << "\"" << std::endl;
//         free(temp_buf);
//         return false;
//     }

//     // Unseal the sealed blob
//     sgx_status_t retval;
//     sgx_status_t ret = unseal_data(global_eid, &retval, temp_buf, fsize);
//     if (ret != SGX_SUCCESS)
//     {
//         print_error_message(ret);
//         free(temp_buf);
//         return false;
//     }
//     else if(retval != SGX_SUCCESS)
//     {
//         print_error_message(retval);
//         free(temp_buf);
//         return false;
//     }

//     free(temp_buf);
   
//     std::cout << "Unseal succeeded." << std::endl;
//     return true;
// }
#endif /*_O_SEAL_H_*/