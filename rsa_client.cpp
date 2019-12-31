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
	struct Rsa_client_data {
		Rsa_client*	client = nullptr;
		uintptr_t	key_id = 0;
	};
}

int	Rsa_client::rsa_private_decrypt (int flen, const unsigned char* from, unsigned char* to, RSA* rsa, int padding)
{
	const uint8_t		command = 1;
	Rsa_client_data*	data = reinterpret_cast<Rsa_client_data*>(RSA_get_app_data(rsa));

	data->client->send_to_server(&command, sizeof(command));
	data->client->send_to_server(&data->key_id, sizeof(data->key_id));
	data->client->send_to_server(&padding, sizeof(padding));
	data->client->send_to_server(&flen, sizeof(flen));
	data->client->send_to_server(from, flen);

	int			plain_len;
	data->client->recv_from_server(&plain_len, sizeof(plain_len));
	if (plain_len > 0) {
		data->client->recv_from_server(to, plain_len);
	}

	return plain_len;
}

int	Rsa_client::rsa_private_encrypt (int flen, const unsigned char* from, unsigned char* to, RSA* rsa, int padding)
{
	const uint8_t		command = 2;
	Rsa_client_data*	data = reinterpret_cast<Rsa_client_data*>(RSA_get_app_data(rsa));

	data->client->send_to_server(&command, sizeof(command));
	data->client->send_to_server(&data->key_id, sizeof(data->key_id));
	data->client->send_to_server(&padding, sizeof(padding));
	data->client->send_to_server(&flen, sizeof(flen));
	data->client->send_to_server(from, flen);

	int			sig_len;
	data->client->recv_from_server(&sig_len, sizeof(sig_len));
	if (sig_len > 0) {
		data->client->recv_from_server(to, sig_len);
	}

	return sig_len;
}

int	Rsa_client::rsa_finish (RSA* rsa)
{
	delete reinterpret_cast<Rsa_client_data*>(RSA_get_app_data(rsa));
	if (const auto default_finish = RSA_meth_get_finish(RSA_get_default_method())) {
		return (*default_finish)(rsa);
	} else {
		return 1;
	}
}

const RSA_METHOD*	Rsa_client::get_rsa_method ()
{
	static RSA_METHOD* ops = NULL;
	if (ops == NULL) {
		ops = RSA_meth_dup(RSA_get_default_method());
		RSA_meth_set_priv_enc(ops, rsa_private_encrypt);
		RSA_meth_set_priv_dec(ops, rsa_private_decrypt);
		RSA_meth_set_finish(ops, rsa_finish);
	}
	return ops;
}

openssl_unique_ptr<EVP_PKEY>	Rsa_client::load_private_key (uintptr_t key_id, RSA* public_rsa)
{
	openssl_unique_ptr<RSA>		rsa(RSA_new());
	if (!rsa) {
		throw Openssl_error(ERR_get_error());
	}

	const BIGNUM* n;
	const BIGNUM* e;
	RSA_get0_key(public_rsa, &n, &e, NULL);
	if (!RSA_set0_key(rsa.get(), BN_dup(n), BN_dup(e), NULL)) {
		throw Openssl_error(ERR_get_error());
	}

	std::unique_ptr<Rsa_client_data> client_data(new Rsa_client_data);
	client_data->client = this;
	client_data->key_id = key_id;
	if (!RSA_set_app_data(rsa.get(), client_data.get())) {
		throw Openssl_error(ERR_get_error());
	}
	RSA_set_method(rsa.get(), get_rsa_method());
	client_data.release(); // After calling RSA_set_method, client_data is owned by rsa.

	openssl_unique_ptr<EVP_PKEY>	private_key(EVP_PKEY_new());
	if (!private_key) {
		throw Openssl_error(ERR_get_error());
	}

	if (!EVP_PKEY_set1_RSA(private_key.get(), rsa.get())) {
		throw Openssl_error(ERR_get_error());
	}

	// private_key increases ref count to rsa, so when rsa goes out of scope it's not actually freed

	return private_key;
}

void	Rsa_client::set_socket (filedesc arg_sock)
{
	sock = std::move(arg_sock);
}

void	Rsa_client::send_to_server (const void* data, size_t len) const
{
	write_all(sock, data, len);
}

void	Rsa_client::recv_from_server (void* data, size_t len) const
{
	if (!read_all(sock, data, len)) {
		throw Key_protocol_error("Server ended connection prematurely");
	}
}
