#include "util.hpp"
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>
#include <netinet/ip.h>

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
	int transparent = 1;
	if (setsockopt(sock_fd, IPPROTO_IP, IP_TRANSPARENT, &transparent, sizeof(transparent)) == -1) {
		throw System_error("setsockopt(IP_TRANSPARENT)", "", errno);
	}
}

void set_not_v6only (int sock_fd)
{
	int v6only = 0;
	if (setsockopt(sock_fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) == -1) {
		throw System_error("setsockopt(IPV6_V6ONLY)", "", errno);
	}
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

	// Prevent this process from being ptraced, so other children running as this UID can't
	// attack us.  Ultimately we should use a dedicated UID for every child process for even
	// better isolation.
	if (prctl(PR_SET_DUMPABLE, 0) == -1) {
		throw System_error("prctl(PR_SET_DUMPABLE)", "", errno);
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
	if (pid == 0) {
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
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_V4MAPPED;
	hints.ai_protocol = 0;

	struct addrinfo*	addrs;
	int			res = getaddrinfo(host.empty() ? NULL : host.c_str(), port.c_str(), &hints, &addrs);
	if (res != 0) {
		throw Configuration_error("Unable to resolve [" + host + "]:" + port + " - " + gai_strerror(res));
	}
	if (addrs->ai_next) {
		freeaddrinfo(addrs);
		throw Configuration_error("[" + host + "]:" + port + " resolves to more than one address");
	}
	std::memcpy(address, addrs->ai_addr, addrs->ai_addrlen);
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

