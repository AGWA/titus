/*
 * Copyright (C) 2014 Andrew Ayer
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Except as contained in this notice, the name(s) of the above copyright
 * holders shall not be used in advertising or otherwise to promote the
 * sale, use or other dealings in this Software without prior written
 * authorization.
 */

// TODO: do this via a configure script:
#ifdef __linux__
#define HAS_PRCTL 1
#define HAS_IP_TRANSPARENT 1
#endif
#ifdef __FreeBSD__
#define HAS_PROCCTL
#endif

#include "util.hpp"
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/resource.h>
#ifdef HAS_PRCTL
#include <sys/prctl.h>
#endif
#ifdef HAS_PROCCTL
#include <sys/procctl.h>
#endif
#include <netdb.h>
#include <pwd.h>
#include <grp.h>
#include <netinet/ip.h>

// TODO: do this via a configure script:
#if defined(__linux__) || defined(RLIMIT_NPROC)
#define HAS_RLIMIT_NPROC
#endif

void set_nonblocking (int fd, bool nonblocking)
{
	int		old_flags = fcntl(fd, F_GETFL);
	if (old_flags == -1) {
		throw System_error("fcntl(F_GETFL)", "", errno);
	}
	int		new_flags = old_flags;
	if (nonblocking) {
		new_flags |= O_NONBLOCK;
	} else {
		new_flags &= ~O_NONBLOCK;
	}
	if (new_flags != old_flags && fcntl(fd, F_SETFL, new_flags) == -1) {
		throw System_error("fcntl(F_SETFL)", "", errno);
	}
}

void set_transparent (int sock_fd)
{
#ifdef HAS_IP_TRANSPARENT
	int transparent = 1;
	if (setsockopt(sock_fd, IPPROTO_IP, IP_TRANSPARENT, &transparent, sizeof(transparent)) == -1) {
		throw System_error("setsockopt(IP_TRANSPARENT)", "", errno);
	}
#else
	throw System_error("setsockopt(IP_TRANSPARENT)", "", ENOSYS);
#endif
}

void set_not_v6only (int sock_fd)
{
	int v6only = 0;
	if (setsockopt(sock_fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) == -1) {
		throw System_error("setsockopt(IPV6_V6ONLY)", "", errno);
	}
}

void set_reuseaddr (int sock_fd)
{
	int reuseaddr = 1;
	if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr)) == -1) {
		throw System_error("setsockopt(SO_REUSEADDR)", "", errno);
	}
}

void disable_tracing ()
{
#ifdef HAS_PRCTL
	if (prctl(PR_SET_DUMPABLE, 0) == -1) {
		throw System_error("prctl(PR_SET_DUMPABLE)", "", errno);
	}
#elif defined(HAS_PROCCTL) && defined(PROC_TRACE_CTL)
	// Available in FreeBSD	10.2-RELEASE and higher
	int arg = PROC_TRACE_CTL_DISABLE_EXEC;
	if (procctl(P_PID, getpid(), PROC_TRACE_CTL, &arg) == -1 && errno != EINVAL) {
		throw System_error("procctl(PROC_TRACE_CTL)", "", errno);
	}
#endif
}

void drop_privileges (const std::string& chroot_directory, uid_t drop_uid, gid_t drop_gid)
{
	// Change root.
	if (!chroot_directory.empty()) {
		if (chroot(chroot_directory.c_str()) == -1) {
			throw System_error("chroot", chroot_directory, errno);
		}
		if (chdir("/") == -1) {
			throw System_error("chdir", "/", errno);
		}
	}

	// Prevent this process from being ptraced/debugged, so other children running as this UID can't
	// attack us.  Ultimately we should use a dedicated UID for every child process for even
	// better isolation.
	disable_tracing();

	// Drop privileges.
	if (drop_gid != static_cast<gid_t>(-1) && setgid(drop_gid) == -1) {
		throw System_error("setgid", "", errno);
	}
	if (drop_gid != static_cast<gid_t>(-1) && setgroups(0, &drop_gid) == -1) { // Note: man page is unclear if 2nd argument can be NULL or not; play it safe by passing it a valid address; it should never be deferenced b/c first argument is 0
		throw System_error("setgroups", "", errno);
	}
	if (drop_uid != static_cast<uid_t>(-1) && setuid(drop_uid) == -1) {
		throw System_error("setuid", "", errno);
	}

#ifdef HAS_RLIMIT_NPROC
	// Prevent this process from forking by setting RLIMIT_NPROC to 0
	struct rlimit		rlim = { 0, 0 };
	if (setrlimit(RLIMIT_NPROC, &rlim) == -1) {
		throw System_error("setrlimit(RLIMIT_NPROC)", "", errno);
	}
#endif
}

void	restrict_file_descriptors ()
{
	// Prevent this process from creating new file descriptors by setting RLIMIT_NOFILE to 0
	struct rlimit		rlim = { 0, 0 };
	if (setrlimit(RLIMIT_NOFILE, &rlim) == -1) {
		throw System_error("setrlimit(RLIMIT_NOFILE)", "", errno);
	}
}


void	write_all (int fd, const void* data, size_t len)
{
	const char*	p = reinterpret_cast<const char*>(data);
	ssize_t		bytes_written;
	while (len > 0 && (bytes_written = write(fd, p, len)) > 0) {
		p += bytes_written;
		len -= bytes_written;
	}
	if (len > 0) {
		throw System_error("write", "", errno);
	}
}
bool	read_all (int fd, void* data, size_t len)
{
	char*		p = reinterpret_cast<char*>(data);
	ssize_t		bytes_read;
	while (len > 0 && (bytes_read = read(fd, p, len)) > 0) {
		p += bytes_read;
		len -= bytes_read;
	}
	if (len > 0 && bytes_read != 0) {
		throw System_error("read", "", errno);
	}
	return len == 0;
}

void daemonize ()
{
	pid_t		pid = fork();
	if (pid == -1) {
		throw System_error("fork", "", errno);
	}
	if (pid != 0) {
		// Exit parent
		_exit(0);
	}
	setsid();

	close(0);
	close(1);
	close(2);
	open("/dev/null", O_RDONLY);
	open("/dev/null", O_WRONLY);
	open("/dev/null", O_WRONLY);
}

void resolve_address (struct sockaddr_in6* address, const std::string& host, const std::string& port)
{
	struct addrinfo		hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = host.empty() ? AF_INET6 : AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_protocol = 0;

	struct addrinfo*	addrs;
	int			res = getaddrinfo(host.empty() ? nullptr : host.c_str(), port.empty() ? nullptr : port.c_str(), &hints, &addrs);
	if (res != 0) {
		throw Configuration_error("Unable to resolve [" + host + "]:" + port + " - " + gai_strerror(res));
	}
	if (addrs->ai_next) {
		freeaddrinfo(addrs);
		throw Configuration_error("[" + host + "]:" + port + " resolves to more than one address");
	}
	if (addrs->ai_family == AF_INET) {
		std::memset(address, '\0', sizeof(*address));
		address->sin6_family = AF_INET6;
		address->sin6_addr.s6_addr[10] = 0xFF;
		address->sin6_addr.s6_addr[11] = 0xFF;
		std::memcpy(&address->sin6_addr.s6_addr[12], &reinterpret_cast<const sockaddr_in*>(addrs->ai_addr)->sin_addr, 4);
		address->sin6_port = reinterpret_cast<const sockaddr_in*>(addrs->ai_addr)->sin_port;
	} else if (addrs->ai_family == AF_INET6) {
		std::memcpy(address, addrs->ai_addr, sizeof(*address));
	} else {
		freeaddrinfo(addrs);
		throw Configuration_error("[" + host + "]:" + port + " resolves to an unknown address family");
	}
	if (port.empty()) {
		address->sin6_port = htons(0);
	}
	freeaddrinfo(addrs);
}

uid_t resolve_user (const std::string& user)
{
	errno = 0;
	struct passwd*		usr = getpwnam(user.c_str());
	if (!usr) {
		throw Configuration_error(user + ": " + (errno ? std::strerror(errno) : "No such user"));
	}
	return usr->pw_uid;
}

gid_t resolve_group (const std::string& group)
{
	errno = 0;
	struct group*		grp = getgrnam(group.c_str());
	if (!grp) {
		throw Configuration_error(group + ": " + (errno ? std::strerror(errno) : "No such group"));
	}
	return grp->gr_gid;
}

filedesc make_unix_socket (const std::string& path, struct sockaddr_un* addr, socklen_t* addr_len)
{
	if (path.size() >= sizeof(addr->sun_path) - 1) {
		throw System_error("make_unix_socket", path, ENAMETOOLONG);
	}
	unlink(path.c_str());

	addr->sun_family = AF_UNIX;
	std::strcpy(addr->sun_path, path.c_str());
	*addr_len = sizeof(addr->sun_family) + path.size();
	filedesc sock;
	if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		throw System_error("socket(AF_UNIX)", "", errno);
	}
	if (bind(sock, reinterpret_cast<struct sockaddr*>(addr), *addr_len) == -1) {
		throw System_error("bind", addr->sun_path, errno);
	}
	return sock;
}

filedesc make_unix_socket (const std::string& path)
{
	struct sockaddr_un addr;
	socklen_t addr_len;
	return make_unix_socket(path, &addr, &addr_len);
}

std::string make_temp_directory ()
{
	char		path[64];
	std::strcpy(path, "/tmp/titus.XXXXXX");
	if (!mkdtemp(path)) {
		throw System_error("mkdtemp", path, errno);
	}
	return path;
}

void set_ssl_options (SSL_CTX* ctx, const std::map<long, bool>& options)
{
	for (auto it(options.begin()); it != options.end(); ++it) {
		if (it->second) {
			SSL_CTX_set_options(ctx, it->first);
		} else {
			SSL_CTX_clear_options(ctx, it->first);
		}
	}

}

openssl_unique_ptr<EC_KEY> get_ecdhcurve (const std::string& name)
{
	int     nid = OBJ_sn2nid(name.c_str());
	if (nid == NID_undef) {
		throw Configuration_error("Unknown ECDH curve `" + name + "'");
	}
	openssl_unique_ptr<EC_KEY>      ecdh(EC_KEY_new_by_curve_name(nid));
	if (!ecdh) {
		throw Configuration_error("Unable to create ECDH curve: " + Openssl_error::message(ERR_get_error()));
	}
	return ecdh;
}

namespace {
	// Avoid the ctype.h functions because they do locale stuff
	inline char	ascii_tolower (char c) { return (c >= 'A' && c <= 'Z' ? c | 32 : c); }
}

bool ascii_streqi (const char* a, const char* b)
{
	while (ascii_tolower(*a) == ascii_tolower(*b)) {
		if (*a == '\0') {
			return true;
		}
		++a;
		++b;
	}
	return false;
}
