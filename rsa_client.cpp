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

#include "rsa_client.hpp"
#include "util.hpp"
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <sys/uio.h>


namespace {
	int	sock = -1;

	void	send_to_server (const void* data, size_t len)
	{
		write_all(sock, data, len);
	}
	void	recv_from_server (void* data, size_t len)
	{
		if (!read_all(sock, data, len)) {
			throw Key_protocol_error("Server ended connection prematurely");
		}
	}

	int	rsa_client_private_decrypt (int flen, const unsigned char* from, unsigned char* to, RSA* rsa, int padding)
	{
		uint8_t		command = 1;
		uintptr_t	key_id = reinterpret_cast<uintptr_t>(RSA_get_app_data(rsa));

		send_to_server(&command, sizeof(command));
		send_to_server(&key_id, sizeof(key_id));
		send_to_server(&padding, sizeof(padding));
		send_to_server(&flen, sizeof(flen));
		send_to_server(from, flen);

		int		plain_len;
		recv_from_server(&plain_len, sizeof(plain_len));
		if (plain_len > 0) {
			recv_from_server(to, plain_len);
		}

		return plain_len;
	}

	int	rsa_client_private_encrypt (int flen, const unsigned char* from, unsigned char* to, RSA* rsa, int padding)
	{
		uint8_t		command = 2;
		uintptr_t	key_id = reinterpret_cast<uintptr_t>(RSA_get_app_data(rsa));

		send_to_server(&command, sizeof(command));
		send_to_server(&key_id, sizeof(key_id));
		send_to_server(&padding, sizeof(padding));
		send_to_server(&flen, sizeof(flen));
		send_to_server(from, flen);

		int		sig_len;
		recv_from_server(&sig_len, sizeof(sig_len));
		if (sig_len > 0) {
			recv_from_server(to, sig_len);
		}

		return sig_len;
	}

	RSA_METHOD*	get_rsa_client_method ()
	{
		static RSA_METHOD ops;
		if (!ops.rsa_priv_enc) {
			ops = *RSA_get_default_method();
			ops.rsa_priv_enc = rsa_client_private_encrypt;
			ops.rsa_priv_dec = rsa_client_private_decrypt;
		}
		return &ops;
	}
}

EVP_PKEY*	rsa_client_load_private_key (uintptr_t key_id, RSA* public_rsa)
{
	EVP_PKEY*	private_key = EVP_PKEY_new();
	if (!private_key) {
		throw Openssl_error(ERR_get_error());
	}

	RSA*		rsa = RSA_new();
	if (!rsa) {
		throw Openssl_error(ERR_get_error());
	}

	rsa->n = BN_dup(public_rsa->n);
	if (!rsa->n) {
		unsigned long	code = ERR_get_error();
		RSA_free(rsa);
		throw Openssl_error(code);
	}
	rsa->e = BN_dup(public_rsa->e);
	if (!rsa->e) {
		unsigned long	code = ERR_get_error();
		RSA_free(rsa);
		throw Openssl_error(code);
	}

	RSA_set_method(rsa, get_rsa_client_method());
	if (!RSA_set_app_data(rsa, reinterpret_cast<void*>(key_id))) {
		unsigned long	code = ERR_get_error();
		RSA_free(rsa);
		throw Openssl_error(code);
	}

	if (!EVP_PKEY_set1_RSA(private_key, rsa)) {
		unsigned long	code = ERR_get_error();
		RSA_free(rsa);
		throw Openssl_error(code);
	}

	RSA_free(rsa); // decrements ref count; private_key still holds a ref to it so it's not actually freed

	return private_key;
}

void	rsa_client_set_socket (int arg_sock)
{
	sock = arg_sock;
}

