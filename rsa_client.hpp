#ifndef RSA_CLIENT_HPP
#define RSA_CLIENT_HPP

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <stdint.h>

EVP_PKEY*	rsa_client_load_private_key (uintptr_t key_id, RSA* public_rsa);
void		rsa_client_set_socket (int fd);

#endif
