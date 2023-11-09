# Dummy makefile, will call the host and enclave makefile when requested.
export CUSTOM_EDL_PATH=../../sdk/edl
export CUSTOM_COMMON_PATH=../../sdk/common

SRC_U = app/
SRC_T = enclave/

# Compilation process, will call the appropriate makefiles.

all: host enclave

host:
	@echo "\033[32mRequest to compile the host part...\033[0m"
	@$(MAKE) -e -C $(SRC_U)

enclave:
	@echo "\033[32mRequest to compile the enclave part...\033[0m"
	@$(MAKE) -e -C $(SRC_T)

clean:
	@$(MAKE) -e -C $(SRC_U) clean
	@$(MAKE) -e -C $(SRC_T) clean

fclean:
	@$(MAKE) -e -C $(SRC_U) fclean
	@$(MAKE) -e -C $(SRC_T) fclean

clean_host:
	@$(MAKE) -e -C $(SRC_U) clean

clean_enclave:
	@$(MAKE) -e -C $(SRC_T) clean

fclean_host:
	@$(MAKE) -e -C $(SRC_U) fclean

fclean_enclave:
	@$(MAKE) -e -C $(SRC_T) fclean

re_host: fclean_host host

re_enclave: fclean_enclave enclave

re: fclean all

# Dummy rules to let make know that those rules are not files.

.PHONY: host enclave clean clean_host clean_enclave fclean_host fclean_enclave fclean re re_host re_enclave
