#include "common.hpp"

// Config (see common.hpp):
std::string		cert_filename;
std::string		key_filename;
Transparency		transparent = TRANSPARENT_OFF;
struct sockaddr_in6	backend_address;
unsigned int		max_handshake_time = 10;
std::string		chroot_directory;
uid_t			drop_uid_network = -1;
gid_t			drop_gid_network = -1;
uid_t			drop_uid_keyserver = -1;
gid_t			drop_gid_keyserver = -1;

// Common state (see common.hpp):
int			listening_sock = -1;
int			children_pipe[2];

// OpenSSL state:
SSL_CTX*		ssl_ctx = NULL;

