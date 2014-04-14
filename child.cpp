#include "child.hpp"
#include "common.hpp"
#include <errno.h>
#include <cstring>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <grp.h>
#include <iostream>
#include <openssl/rand.h>

namespace {
	void init_signals ()
	{
		signal(SIGINT, SIG_DFL);
		signal(SIGTERM, SIG_DFL);
		signal(SIGCHLD, SIG_DFL);
		signal(SIGPIPE, SIG_IGN);
		sigset_t empty_sigset;
		sigemptyset(&empty_sigset);
		sigprocmask(SIG_SETMASK, &empty_sigset, NULL);
	}

	class Pump {
		enum Result {
			pump_nothing,
			pump_successful,
			pump_read_blocked,
			pump_write_blocked
		};
		enum State {
			socket_open,			// socket is open
			socket_shutdown,		// socket has been shutdown
			socket_shutdown_proxied		// socket has been shutdown and the shutdown has been proxied
		};

		int		client_sock;
		SSL*		client_ssl;
		int		backend_sock;

		State		client_read_state;
		bool		client_buffer[4096];	// read from client, written to backend
		size_t		client_buffer_len;
		size_t		client_buffer_proxied;	// # of bytes proxied so far to backend

		State		backend_read_state;
		bool		backend_buffer[4096];	// read from backend, written to client
		size_t		backend_buffer_len;
		size_t		backend_buffer_proxied;	// # of bytes proxied so far to client

		Result handle_ssl_error (const char* where, int res)
		{
			int	err = SSL_get_error(client_ssl, res);
			if (err == SSL_ERROR_WANT_READ) {
				return pump_read_blocked;
			} else if (err == SSL_ERROR_WANT_WRITE) {
				return pump_write_blocked;
			} else if (err == SSL_ERROR_SYSCALL) {
				unsigned long	err_code = ERR_get_error();
				if (err_code) {
					throw Openssl_error(err_code);
				} else {
					throw System_error(where, "", errno);
				}
			} else if (err == SSL_ERROR_SSL) {
				throw Openssl_error(ERR_get_error());
			} else {
				throw Openssl_error(0);
			}
		}

		Result pump_client_reads ()
		{
			if (client_read_state != socket_open || client_buffer_len) {
				return pump_nothing;
			}
			int res = SSL_read(client_ssl, client_buffer, sizeof(client_buffer));
			if (res < 0) {
				return handle_ssl_error("SSL_read", res);
			}
			if (res == 0) {
				// TODO: call SSL_get_error() to determine if the TLS connection was properly shut down ?
				client_read_state = socket_shutdown;
			}
			client_buffer_len = res;
			return pump_successful;
		}

		Result pump_client_writes ()
		{
			if (!backend_buffer_len) {
				if (backend_read_state == socket_shutdown) {
					int res = SSL_shutdown(client_ssl);
					if (res < 0) {
						return handle_ssl_error("SSL_shutdown", res);
					}
					backend_read_state = socket_shutdown_proxied;
					return pump_successful;
				}

				return pump_nothing;
			}
			int res = SSL_write(client_ssl, backend_buffer + backend_buffer_proxied, backend_buffer_len - backend_buffer_proxied);
			if (res < 0) {
				return handle_ssl_error("SSL_write", res);
			}
			if (res == 0) {
				// TODO: handle this _write_ shutdown
			}
			backend_buffer_proxied += res;
			if (backend_buffer_proxied == backend_buffer_len) {
				backend_buffer_len = 0;
				backend_buffer_proxied = 0;
			}
			return pump_successful;
		}

		Result pump_backend_reads ()
		{
			if (backend_read_state != socket_open || backend_buffer_len) {
				return pump_nothing;
			}
			ssize_t	res = read(backend_sock, backend_buffer, sizeof(backend_buffer));
			if (res < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					return pump_read_blocked;
				}
				throw System_error("read", "backend_sock", errno);
			}
			if (res == 0) {
				backend_read_state = socket_shutdown;
			}
			backend_buffer_len = res;
			return pump_successful;
		}

		Result pump_backend_writes ()
		{
			if (!client_buffer_len) {
				if (client_read_state == socket_shutdown) {
					if (shutdown(backend_sock, SHUT_WR) == -1) {
						throw System_error("shutdown(SHUT_WR)", "backend_sock", errno);
					}
					client_read_state = socket_shutdown_proxied;
					return pump_successful;
				}
				return pump_nothing;
			}
			ssize_t	res = write(backend_sock, client_buffer + client_buffer_proxied, client_buffer_len - client_buffer_proxied);
			if (res < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					return pump_write_blocked;
				}
				throw System_error("write", "backend_sock", errno);
			}
			client_buffer_proxied += res;
			if (client_buffer_proxied == client_buffer_len) {
				client_buffer_len = 0;
				client_buffer_proxied = 0;
			}
			return pump_successful;
		}
	public:
		Pump (int arg_client_sock, SSL* arg_client_ssl, int arg_backend_sock)
		{
			client_sock = arg_client_sock;
			client_ssl = arg_client_ssl;
			backend_sock = arg_backend_sock;

			client_read_state = socket_open;
			client_buffer_len = 0;
			client_buffer_proxied = 0;

			backend_read_state = socket_open;
			backend_buffer_len = 0;
			backend_buffer_proxied = 0;
		}

		void operator() ()
		{
			struct pollfd	fds[2];
			fds[0].fd = client_sock;
			fds[1].fd = backend_sock;

			while (true) {
				Result	client_read_result = pump_client_reads();
				Result	backend_read_result = pump_backend_reads();

				Result	client_write_result = pump_client_writes();
				Result	backend_write_result = pump_backend_writes();

				if (client_read_result != pump_successful &&
						backend_read_result != pump_successful &&
						client_write_result != pump_successful &&
						backend_write_result != pump_successful) {

					// No forward progress was made at all -> poll() until we can make progress
					fds[0].events = 0;
					fds[1].events = 0;
					if (client_read_result == pump_read_blocked ||
							client_write_result == pump_read_blocked) {
						fds[0].events |= POLLIN;
					}
					if (backend_read_result == pump_read_blocked ||
							backend_write_result == pump_read_blocked) {
						fds[1].events |= POLLIN;
					}
					if (client_read_result == pump_write_blocked ||
							client_write_result == pump_write_blocked) {
						fds[0].events |= POLLOUT;
					}
					if (backend_read_result == pump_write_blocked ||
							backend_write_result == pump_write_blocked) {
						fds[1].events |= POLLOUT;
					}

					if (fds[0].events == 0 && fds[1].events == 0) {
						// This'll happen when the connection winds down cleanly
						break;
					}

					if (poll(fds, 2, -1) == -1) {
						throw System_error("poll", "", errno);
					}
				}
			}

			//TODO: finish SSL shutdown ?
		}
	};

	void proxy (int client_sock, SSL* client_ssl, int backend_sock)
	{
		Pump pump(client_sock, client_ssl, backend_sock);
		pump();
	}
}


int child_main ()
try {
	init_signals();

	// reseed OpenSSL RNG b/c we just forked
	if (RAND_poll() != 1) {
		throw Openssl_error(ERR_get_error());
	}

	// Terminology in this function:
	//  "client" is the TLS client connecting to us.
	//  "backend" is the server to which we connect and to which we relay the clear text.

	close(children_pipe[0]);

	// Create the backend socket.  Since setting transparency requires privilege,
	// we do it while we're still root.
	int			backend_sock = socket(AF_INET6, SOCK_STREAM, 0);
	if (backend_sock == -1) {
		throw System_error("socket", "", errno);
	}

	set_not_v6only(backend_sock);
	if (transparent) {
		set_transparent(backend_sock);
	}

	// Change root.
	if (chroot_directory) {
		if (chroot(chroot_directory) == -1) {
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

	// Accept client connection.
	int			client_sock;
	struct sockaddr_in6	client_address;
	socklen_t		client_address_len = sizeof(client_address);
	while ((client_sock = accept(listening_sock, reinterpret_cast<struct sockaddr*>(&client_address), &client_address_len)) == -1 && (errno == ECONNABORTED || errno == EINTR));

	if (client_sock == -1) {
		throw System_error("accept", "", errno);
	}

	close(listening_sock);

	// Write our PID to the parent process over the pipe so that it knows we are no longer idle.
	{
		pid_t		our_pid = getpid();
		write(children_pipe[1], &our_pid, sizeof(our_pid));
	}
	close(children_pipe[1]);

	// SSL Handshake
	SSL*			ssl = SSL_new(ssl_ctx);
	if (!SSL_set_fd(ssl, client_sock)) {
		throw Openssl_error(ERR_get_error());
	}
	int			accept_res;
	if ((accept_res = SSL_accept(ssl)) != 1) {
		int		err = SSL_get_error(ssl, accept_res);
		if (err == SSL_ERROR_SYSCALL) {
			unsigned long	code = ERR_get_error();
			if (code) {
				throw Openssl_error(code);
			} else if (accept_res == 0) {
				// Client disconnected prematurely
				return 0;
			} else {
				throw System_error("SSL_accept", "", errno);
			}
		} else if (err == SSL_ERROR_SSL) {
			throw Openssl_error(ERR_get_error());
		} else {
			std::clog << "Unknown TLS error: " << err << std::endl;
			return 5;
		}
	}

	if (transparent) {
		// Impersonate the client when talking to the backend.
		if (bind(backend_sock, reinterpret_cast<const struct sockaddr*>(&client_address), client_address_len) == -1) {
			throw System_error("bind", "", errno);
		}

		// The backend address is the local address of the client socket.  Since this is a transparent
		// proxy socket, the local address is not actually the local address, but the original address before proxying.
		struct sockaddr_in6	backend_address;
		socklen_t		backend_address_len = sizeof(backend_address);
		if (getsockname(client_sock, reinterpret_cast<struct sockaddr*>(&backend_address), &backend_address_len) == -1) {
			throw System_error("getsockname", "", errno);
		}

		if (connect(backend_sock, reinterpret_cast<const struct sockaddr*>(&backend_address), backend_address_len) == -1) {
			throw System_error("connect", "", errno);
		}
	} else {
		// TODO: non-transparent operation

		struct sockaddr_in6	backend_address;
		socklen_t		backend_address_len = sizeof(backend_address);
		if (getsockname(client_sock, reinterpret_cast<struct sockaddr*>(&backend_address), &backend_address_len) == -1) { // TEMP
			throw System_error("getsockname", "", errno);
		}
		backend_address.sin6_port = htons(8701); // TEMP

		if (connect(backend_sock, reinterpret_cast<const struct sockaddr*>(&backend_address), backend_address_len) == -1) {
			throw System_error("connect", "", errno);
		}
	}

	set_nonblocking(backend_sock, true);
	set_nonblocking(client_sock, true);

	proxy(client_sock, ssl, backend_sock);

	SSL_free(ssl);
	close(client_sock);
	close(backend_sock);

	return 0;
} catch (const System_error& error) {
	std::clog << "System error in child: " << error.syscall;
	if (!error.target.empty()) {
		std::clog << ": " << error.target;
	}
	std::clog << ": " << std::strerror(errno) << std::endl;
	return 3;
} catch (const Openssl_error& error) {
	std::clog << "OpenSSL error in child: " << error.message() << std::endl;
	return 4;
}

