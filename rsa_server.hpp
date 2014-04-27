#ifndef RSA_SERVER_HPP
#define RSA_SERVER_HPP

#include <openssl/rsa.h>

void		run_rsa_server (RSA*, int sock);

#endif
