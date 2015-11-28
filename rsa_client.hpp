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

#ifndef RSA_CLIENT_HPP
#define RSA_CLIENT_HPP

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <stdint.h>
#include "util.hpp"
#include "filedesc.hpp"

class Rsa_client {
	filedesc		sock;

	void			send_to_server (const void* data, size_t len) const;
	void			recv_from_server (void* data, size_t len) const;

	static int		rsa_private_decrypt (int flen, const unsigned char* from, unsigned char* to, RSA* rsa, int padding);
	static int		rsa_private_encrypt (int flen, const unsigned char* from, unsigned char* to, RSA* rsa, int padding);
	static int		rsa_finish (RSA* rsa);
	static const RSA_METHOD* get_rsa_method ();
public:
	// Note: you can't move Rsa_clients because doing so would leave
	// dangling pointers in all the private keys created from it.
	Rsa_client () = default;
	Rsa_client (const Rsa_client&) = delete;
	Rsa_client (Rsa_client&&) = delete;
	Rsa_client& operator= (const Rsa_client&) = delete;
	Rsa_client& operator= (Rsa_client&&) = delete;

	openssl_unique_ptr<EVP_PKEY>	load_private_key (uintptr_t key_id, RSA* public_rsa);
	void				set_socket (filedesc);
};

#endif
