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

#ifndef DH_HPP
#define DH_HPP

#include <openssl/dh.h>
#include "util.hpp"

extern const unsigned char dh_group14_prime[256];
extern const unsigned char dh_group14_generator[1];
extern const unsigned char dh_group15_prime[384];
extern const unsigned char dh_group15_generator[1];
extern const unsigned char dh_group16_prime[512];
extern const unsigned char dh_group16_generator[1];

openssl_unique_ptr<DH> make_dh (const unsigned char* prime, size_t prime_len, const unsigned char* generator, size_t generator_len);

template<size_t prime_len, size_t generator_len> openssl_unique_ptr<DH> make_dh (const unsigned char (&prime)[prime_len], const unsigned char (&generator)[generator_len])
{
	return make_dh(prime, prime_len, generator, generator_len);
}

// Returns a DH group appropriate for pairing with an RSA key of the given modulus size:
// (may return null if we don't have a DH group strong enough)
openssl_unique_ptr<DH> make_dh_for_rsa_size (unsigned int modulus_size_in_bits);

#endif
