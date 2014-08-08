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

// Config (see common.hpp):
std::vector<Vhost>	vhosts;
Transparency		transparent = TRANSPARENT_OFF;
unsigned int		max_handshake_time = 10;
std::string		chroot_directory;
uid_t			drop_uid_network = -1;
gid_t			drop_gid_network = -1;
uid_t			drop_uid_keyserver = -1;
gid_t			drop_gid_keyserver = -1;

// Common state (see common.hpp):
int			listening_sock = -1;
int			children_pipe[2];
struct sockaddr_un	keyserver_sockaddr;
socklen_t		keyserver_sockaddr_len;

// OpenSSL state:
SSL_CTX*		ssl_ctx = NULL;

