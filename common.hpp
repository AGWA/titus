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

#ifndef COMMON_HPP
#define COMMON_HHP

#include "util.hpp"
#include "rsa_client.hpp"
#include <string>
#include <vector>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <netinet/ip.h>

typedef uintptr_t Vhost_id;

struct Vhost {
	Vhost_id				id = 0;
	struct sockaddr_in6			local_address;
	struct sockaddr_in6			backend_address;
	bool					servername_set = false;
	std::string				servername;
	std::string				key_filename;
	openssl_unique_ptr<SSL_CTX>		ssl_ctx;

	Vhost ()
	{
		std::memset(&local_address, 0, sizeof(local_address));
		std::memset(&backend_address, 0, sizeof(backend_address));
	}

	bool matches_servername (const char* arg_servername) const
	{
		return !servername_set || ascii_streqi(servername.c_str(), arg_servername);
	}
};

// Config:
extern std::vector<Vhost>	vhosts;			// sorted in order of vhost ID, starting from 0, strictly increasing
extern Transparency		transparent;
extern unsigned int		max_handshake_time;	// TLS handshake must complete within this # of seconds
extern std::string		chroot_directory;	// empty to not chroot
extern uid_t			drop_uid_network;	// UID for process that talks to network (-1 to not change)
extern gid_t			drop_gid_network;	// GID for process that talks to network (-1 to not change)
extern uid_t			drop_uid_keyserver;	// UID for key server process (-1 to not change)
extern gid_t			drop_gid_keyserver;	// GID for key server process (-1 to not change)

// State:
extern int			listening_sock;
extern int			children_pipe[2];		// Used by children to tell us when they accept a connection
extern struct sockaddr_un	keyserver_sockaddr;
extern socklen_t		keyserver_sockaddr_len;
extern Vhost*			active_vhost;
extern Rsa_client		rsa_client;

#endif
