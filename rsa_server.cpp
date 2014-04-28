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
	void	rsa_server_ping (RSA*, int sock)
	{
		uint8_t		pong = 0;
		send_to_client(sock, &pong, sizeof(pong));
	}
	void	rsa_server_private_decrypt (RSA* rsa, int sock)
	{
		uintptr_t	key_id;
		int		padding;
		int		flen;

		recv_from_client(sock, &key_id, sizeof(key_id));
		recv_from_client(sock, &padding, sizeof(padding));
		recv_from_client(sock, &flen, sizeof(flen));

		if (flen < 0 || flen > 65536) {
			throw Key_protocol_error("Client sent invalid flen value");
		}

		unsigned char*	from = new unsigned char[flen];
		recv_from_client(sock, from, flen);

		unsigned char*	to = new unsigned char[RSA_size(rsa)];
		int		plain_len = RSA_private_decrypt(flen, from, to, rsa, padding);

		send_to_client(sock, &plain_len, sizeof(plain_len));
		if (plain_len > 0) {
			send_to_client(sock, to, plain_len);
		}

		// TODO (low priority): don't leak from/to if there's an exception (C++11: use unique_ptr)
		delete[] to;
		delete[] from;
	}
	void	rsa_server_private_encrypt (RSA* rsa, int sock)
	{
		uintptr_t	key_id;
		int		padding;
		int		flen;

		recv_from_client(sock, &key_id, sizeof(key_id));
		recv_from_client(sock, &padding, sizeof(padding));
		recv_from_client(sock, &flen, sizeof(flen));

		if (flen < 0 || flen > 65536) {
			throw Key_protocol_error("Client sent invalid flen value");
		}

		unsigned char*	from = new unsigned char[flen];
		recv_from_client(sock, from, flen);

		unsigned char*	to = new unsigned char[RSA_size(rsa)];
		int		sig_len = RSA_private_encrypt(flen, from, to, rsa, padding);

		send_to_client(sock, &sig_len, sizeof(sig_len));
		if (sig_len > 0) {
			send_to_client(sock, to, sig_len);
		}

		// TODO (low priority): don't leak from/to if there's an exception (C++11: use unique_ptr)
		delete[] to;
		delete[] from;
	}
}

void	run_rsa_server (RSA* rsa, int sock)
{
	uint8_t	command;
	while (read_all(sock, &command, sizeof(command))) {
		if (command == 0) {
			rsa_server_ping(rsa, sock);
		} else if (command == 1) {
			rsa_server_private_decrypt(rsa, sock);
		} else if (command == 2) {
			rsa_server_private_encrypt(rsa, sock);
		} else {
			throw Key_protocol_error("Client sent unknown command");
		}
	}
}

