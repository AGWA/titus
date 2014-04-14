#ifndef DH_HPP
#define DH_HPP

#include <openssl/dh.h>

extern const unsigned char dh_group14_prime[256];
extern const unsigned char dh_group14_generator[1];
extern const unsigned char dh_group15_prime[384];
extern const unsigned char dh_group15_generator[1];
extern const unsigned char dh_group16_prime[512];
extern const unsigned char dh_group16_generator[1];

DH* make_dh (const unsigned char* prime, size_t prime_len, const unsigned char* generator, size_t generator_len);

template<size_t prime_len, size_t generator_len> DH* make_dh (const unsigned char (&prime)[prime_len], const unsigned char (&generator)[generator_len])
{
	return make_dh(prime, prime_len, generator, generator_len);
}

#endif
