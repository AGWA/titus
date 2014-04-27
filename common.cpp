#include "common.hpp"

// Config (see common.hpp):
bool			transparent = false;
unsigned int		min_spare_children = 3;
unsigned int		max_children = 100;
unsigned int		max_handshake_time = 10;
const char*		chroot_directory = NULL;
uid_t			drop_uid = -1;
gid_t			drop_gid = -1;

// Common state (see common.hpp):
int			listening_sock = -1;
int			children_pipe[2];

// OpenSSL state:
SSL_CTX*		ssl_ctx = NULL;

