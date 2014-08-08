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

#include "rsa_server.hpp"
#include "util.hpp"
#include <stdint.h>
#include <openssl/rsa.h>

namespace {
	void	send_to_client (int sock, const void* data, size_t len)
	{
		write_all(sock, data, len);
	}
	void	recv_from_client (int sock, void* data, size_t len)
	{
		if (!read_all(sock, data, len)) {
			throw Key_protocol_error("Client ended connection prematurely");
		}
	}
	void	rsa_server_private_decrypt (const std::vector<RSA*>& keys, int sock)
	{
		uintptr_t	key_id;
		int		padding;
		int		flen;

		recv_from_client(sock, &key_id, sizeof(key_id));
		recv_from_client(sock, &padding, sizeof(padding));
		recv_from_client(sock, &flen, sizeof(flen));

		if (key_id >= keys.size()) {
			throw Key_protocol_error("Client sent unknown key ID");
		}
		if (flen < 0 || flen > 65536) {
			throw Key_protocol_error("Client sent invalid flen value");
		}

		unsigned char*	from = new unsigned char[flen];
		recv_from_client(sock, from, flen);

		unsigned char*	to = new unsigned char[RSA_size(keys[key_id])];
		int		plain_len = RSA_private_decrypt(flen, from, to, keys[key_id], padding);

		send_to_client(sock, &plain_len, sizeof(plain_len));
		if (plain_len > 0) {
			send_to_client(sock, to, plain_len);
		}

		// TODO (low priority): don't leak from/to if there's an exception (C++11: use unique_ptr)
		delete[] to;
		delete[] from;
	}
	void	rsa_server_private_encrypt (const std::vector<RSA*>& keys, int sock)
	{
		uintptr_t	key_id;
		int		padding;
		int		flen;

		recv_from_client(sock, &key_id, sizeof(key_id));
		recv_from_client(sock, &padding, sizeof(padding));
		recv_from_client(sock, &flen, sizeof(flen));

		if (key_id >= keys.size()) {
			throw Key_protocol_error("Client sent unknown key ID");
		}
		if (flen < 0 || flen > 65536) {
			throw Key_protocol_error("Client sent invalid flen value");
		}

		unsigned char*	from = new unsigned char[flen];
		recv_from_client(sock, from, flen);

		unsigned char*	to = new unsigned char[RSA_size(keys[key_id])];
		int		sig_len = RSA_private_encrypt(flen, from, to, keys[key_id], padding);

		send_to_client(sock, &sig_len, sizeof(sig_len));
		if (sig_len > 0) {
			send_to_client(sock, to, sig_len);
		}

		// TODO (low priority): don't leak from/to if there's an exception (C++11: use unique_ptr)
		delete[] to;
		delete[] from;
	}
}

void	run_rsa_server (const std::vector<RSA*>& keys, int sock)
{
	uint8_t	command;
	while (read_all(sock, &command, sizeof(command))) {
		if (command == 1) {
			rsa_server_private_decrypt(keys, sock);
		} else if (command == 2) {
			rsa_server_private_encrypt(keys, sock);
		} else {
			throw Key_protocol_error("Client sent unknown command");
		}
	}
}

