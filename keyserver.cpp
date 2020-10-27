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

#include "common.hpp"
#include "util.hpp"
#include "rsa_server.hpp"
#include <iostream>
#include <cstdio>
#include <signal.h>
#include <unistd.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <vector>

struct Key_server {
	filedesc				sock;
	std::vector<openssl_unique_ptr<RSA>>	keys;

	static void init_signals ()
	{
		signal(SIGINT, SIG_DFL);
		signal(SIGTERM, SIG_DFL);
		signal(SIGCHLD, SIG_IGN);
		signal(SIGPIPE, SIG_IGN);

		sigset_t empty_sigset;
		sigemptyset(&empty_sigset);
		sigprocmask(SIG_SETMASK, &empty_sigset, nullptr);
	}

	static int child_main (Key_server& keyserver, filedesc client_sock)
	try {
		// Close file descriptors we don't need
		keyserver.sock.close();

		// Reseed OpenSSL RNG b/c we just forked
		if (RAND_poll() != 1) {
			throw Openssl_error(ERR_get_error());
		}

		// Drop privileges
		drop_privileges(chroot_directory, drop_uid_keyserver, drop_gid_keyserver);
		restrict_file_descriptors();

		// Read and respond to RSA operations
		run_rsa_server(std::move(keyserver.keys), std::move(client_sock));
		return 0;
	} catch (const System_error& error) {
		std::clog << "System error in key server child: " << error.syscall;
		if (!error.target.empty()) {
			std::clog << ": " << error.target;
		}
		std::clog << ": " << std::strerror(error.number) << std::endl;
		return 3;
	} catch (const Openssl_error& error) {
		std::clog << "OpenSSL error in key server child: " << error.message() << std::endl;
		return 4;
	} catch (const Key_protocol_error& error) {
		std::clog << "Key protocol error in key server child: " << error.message << std::endl;
		return 6;
	}
};

int keyserver_main (filedesc arg_keyserver_sock)
try {
	Key_server	keyserver;
	keyserver.sock = std::move(arg_keyserver_sock);
	Key_server::init_signals();

	// Close file descriptors we don't need
	close(listening_sock);

	// Reseed OpenSSL RNG b/c we just forked
	if (RAND_poll() != 1) {
		throw Openssl_error(ERR_get_error());
	}

	// Load private keys
	keyserver.keys.reserve(vhosts.size());
	for (std::vector<Vhost>::iterator vhost(vhosts.begin()); vhost != vhosts.end(); ++vhost) {
		cstdio_unique_ptr<std::FILE>	fp(std::fopen(vhost->key_filename.c_str(), "r"));
		if (!fp) {
			throw System_error("fopen", vhost->key_filename, errno);
		}

		openssl_unique_ptr<RSA>		rsa(PEM_read_RSAPrivateKey(fp.get(), nullptr, nullptr, nullptr));
		if (!rsa) {
			throw Openssl_error(ERR_get_error());
		}
		keyserver.keys.push_back(std::move(rsa));
	}

	// Accept and service connections
	while (true) {
		filedesc	client_sock(accept(keyserver.sock, nullptr, nullptr));
		if (client_sock == -1) {
			if (errno == ECONNABORTED) {
				continue;
			}
			throw System_error("accept", "", errno);
		}
		spawn(Key_server::child_main, std::ref(keyserver), std::move(client_sock));
	}

	return 0;
} catch (const System_error& error) {
	std::clog << "System error in key server: " << error.syscall;
	if (!error.target.empty()) {
		std::clog << ": " << error.target;
	}
	std::clog << ": " << std::strerror(error.number) << std::endl;
	return 3;
} catch (const Openssl_error& error) {
	std::clog << "OpenSSL error in key server: " << error.message() << std::endl;
	return 4;
}

