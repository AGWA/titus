#ifndef COMMON_HPP
#define COMMON_HHP

#include <string>
#include <sys/types.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>
#include <cctype>
#include <cstdlib>

struct System_error {
	std::string	syscall;
	std::string	target;
	int		number;

	System_error (const std::string& arg_syscall, const std::string& arg_target, int arg_number)
	: syscall(arg_syscall), target(arg_target), number(arg_number) { }
};
struct Openssl_error {
	unsigned long	code;
	explicit Openssl_error (unsigned long arg_code) : code(arg_code) { }

	std::string	message () const { return message(code); }

	static std::string message (unsigned long code)
	{
		char buf[120];
		ERR_error_string_n(code, buf, sizeof(buf));
		return buf;
	}
};
struct Configuration_error {
	std::string	message;
	explicit Configuration_error (const std::string& arg_message) : message(arg_message) { }
};

void set_nonblocking (int fd, bool nonblocking);
void set_transparent (int sock_fd);
void set_not_v6only (int sock_fd);

// Config:
extern bool			transparent;
extern unsigned int		min_spare_children;	// Minimum number of children ready and waiting to accept()
extern unsigned int		max_children;		// Absolute maximum number of children, spare or not
extern unsigned int		max_handshake_time;	// TLS handshake must complete within this # of seconds
extern const char*		chroot_directory;	// NULL to not chroot
extern uid_t			drop_uid;		// -1 to not change UID
extern gid_t			drop_gid;		// -1 to not change GID

// State:
extern int			listening_sock;
extern int			children_pipe[2];		// Used by children to tell us when they accept a connection

// OpenSSL state:
extern SSL_CTX*			ssl_ctx;


inline void ssl_ctx_set_option (long option, bool state)
{
	if (state) {
		SSL_CTX_set_options(ssl_ctx, option);
	} else {
		SSL_CTX_clear_options(ssl_ctx, option);
	}
}


inline bool parse_config_bool (const char* str)
{
	if (strcasecmp(str, "yes") == 0 ||
			strcasecmp(str, "true") == 0 ||
			strcasecmp(str, "on") == 0 ||
			(std::isdigit(str[0]) && std::atoi(str) > 0)) {
		return true;
	} else if (strcasecmp(str, "no") == 0 ||
			strcasecmp(str, "false") == 0 ||
			strcasecmp(str, "off") == 0 ||
			(std::isdigit(str[0]) && std::atoi(str) == 0)) {
		return false;
	} 
	throw Configuration_error(std::string("Invalid yes/no value `") + str + "'");
}
inline bool parse_config_bool (const std::string& str) { return parse_config_bool(str.c_str()); }

#endif
