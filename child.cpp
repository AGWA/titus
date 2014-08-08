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

#include "child.hpp"
#include "common.hpp"
#include "util.hpp"
#include "rsa_client.hpp"
#include <errno.h>
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <grp.h>
#include <iostream>
#include <openssl/rand.h>

namespace {
	void init_signals ()
	{
		signal(SIGINT, SIG_DFL);
		signal(SIGALRM, SIG_DFL);
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
			fd_set		rfds;
			fd_set		wfds;
			FD_ZERO(&rfds);
			FD_ZERO(&wfds);

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
					int		max_fd = -1;
					if (client_read_result == pump_read_blocked ||
							client_write_result == pump_read_blocked) {
						FD_SET(client_sock, &rfds);
						max_fd = std::max(max_fd, client_sock);
					} else {
						FD_CLR(client_sock, &rfds);
					}
					if (backend_read_result == pump_read_blocked ||
							backend_write_result == pump_read_blocked) {
						FD_SET(backend_sock, &rfds);
						max_fd = std::max(max_fd, backend_sock);
					} else {
						FD_CLR(backend_sock, &rfds);
					}
					if (client_read_result == pump_write_blocked ||
							client_write_result == pump_write_blocked) {
						FD_SET(client_sock, &wfds);
						max_fd = std::max(max_fd, client_sock);
					} else {
						FD_CLR(client_sock, &wfds);
					}
					if (backend_read_result == pump_write_blocked ||
							backend_write_result == pump_write_blocked) {
						FD_SET(backend_sock, &wfds);
						max_fd = std::max(max_fd, backend_sock);
					} else {
						FD_CLR(backend_sock, &wfds);
					}

					if (max_fd == -1) {
						// This'll happen when the connection winds down cleanly
						break;
					}

					if (select(max_fd + 1, &rfds, &wfds, NULL, NULL) == -1) {
						throw System_error("select", "", errno);
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


int child_main (void*)
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

	// Connect to the key server over a UNIX domain socket. Do this while we're still
	// privileged since it requires accessing the filesystem.
	int			keyserver_client_sock;
	if ((keyserver_client_sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		throw System_error("socket(AF_UNIX)", "", errno);
	}
	if (connect(keyserver_client_sock, reinterpret_cast<struct sockaddr*>(&keyserver_sockaddr), keyserver_sockaddr_len) == -1) {
		throw System_error("connect", keyserver_sockaddr.sun_path, errno);
	}

	rsa_client_set_socket(keyserver_client_sock);

	// Create the backend socket.  Since setting transparency requires privilege,
	// we do it while we're still root.
	int			backend_sock = socket(AF_INET6, SOCK_STREAM, 0);
	if (backend_sock == -1) {
		throw System_error("socket", "", errno);
	}

	set_not_v6only(backend_sock);
	if (transparent != TRANSPARENT_OFF) {
		set_transparent(backend_sock);
	}

	drop_privileges(chroot_directory, drop_uid_network, drop_gid_network);

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

	// Prevent the creation of new file descriptors.
	restrict_file_descriptors();

	// SSL Handshake
	SSL*			ssl = SSL_new(ssl_ctx);
	if (!SSL_set_fd(ssl, client_sock)) {
		throw Openssl_error(ERR_get_error());
	}
	alarm(max_handshake_time);	// This is a very basic anti-DoS measure. Once the handshake is
					// complete, we rely on the backend to handle timeouts.
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
	alarm(0);

	if (transparent != TRANSPARENT_OFF) {
		// Impersonate the client when talking to the backend.
		if (bind(backend_sock, reinterpret_cast<const struct sockaddr*>(&client_address), client_address_len) == -1) {
			if (errno != EADDRINUSE) {
				throw System_error("bind", "", errno);
			}

			// If we get EADDRINUSE it means the client is local so there is no way
			// to impersonate the port number.  Zero out the port number so one is
			// assigned dynamically.  (Unfortunately the backend won't see the true source port
			// number, but backends generally only care about source IP address.)
			client_address.sin6_port = 0;
			if (bind(backend_sock, reinterpret_cast<const struct sockaddr*>(&client_address), client_address_len) == -1) {
				throw System_error("bind", "", errno);
			}
		}
	}

	if (transparent == TRANSPARENT_ON) {
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
		if (std::memcmp(&backend_address.sin6_addr, &in6addr_any, sizeof(struct in6_addr)) == 0) {
			// Backend IP address not specified, so use the local address of the client socket
			struct sockaddr_in6	local_address;
			socklen_t		local_address_len = sizeof(local_address);
			if (getsockname(client_sock, reinterpret_cast<struct sockaddr*>(&local_address), &local_address_len) == -1) {
				throw System_error("getsockname", "", errno);
			}
			std::memcpy(&backend_address.sin6_addr, &local_address.sin6_addr, sizeof(struct in6_addr));
		}

		socklen_t		backend_address_len = sizeof(backend_address);
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
	std::clog << ": " << std::strerror(error.number) << std::endl;
	return 3;
} catch (const Openssl_error& error) {
	std::clog << "OpenSSL error in child: " << error.message() << std::endl;
	return 4;
} catch (const Key_protocol_error& error) {
	std::clog << "Key protocol error in child: " << error.message << std::endl;
	return 6;
}

