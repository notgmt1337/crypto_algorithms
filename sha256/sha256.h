//License: GNU General Public License, Version 3
/*
 *   sha256.h - Definitions file for the C implementation of the SHA256 cryptographic algorithm
 *   
 *   Original author: George Tridimas <tridimasg@cardiff.ac.uk>
 */
#ifndef SHA256_H
#define SHA256_H
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define RotR(A, n) ((A >> (n)) | (A << (32 - n)))
#define ShR(A, n) (A >> n)

#define Ch(X, Y, Z) ((X & Y) ^ ((~X) & Z))
#define Maj(X, Y, Z) ((X & Y)^(X & Z)^(Y & Z))
#define S0(X) (RotR(X, 2) ^ RotR(X, 13) ^ RotR(X, 22))
#define S1(X) (RotR(X, 6) ^ RotR(X, 11) ^ RotR(X, 25))
#define s0(X) (RotR(X, 7) ^ RotR(X, 18) ^ ShR(X, 3))
#define s1(X) (RotR(X, 17) ^ RotR(X, 19) ^ ShR(X, 10))
#define mask(x) ((((uint64_t) 1) << (x)) + (((uint64_t) 1) << (x - 1)) + (((uint64_t) 1) << (x - 2)) + (((uint64_t) 1) << (x - 3)) + (((uint64_t) 1) << (x - 4)) + (((uint64_t) 1) << (x - 5)) + (((uint64_t) 1) << (x - 6)) + (((uint64_t) 1) << (x - 7)))


static const uint32_t K[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

typedef struct SHA256Context{
	const char* message;
    uint64_t length_in_bits;
	uint16_t k;
	uint64_t padded_length_in_bits;
	uint8_t* padded;
	uint32_t hashes[8];
} Context;

static void init_ctx(Context* ctx, const char* message);

static void pad_ctx(Context* ctx);

static void compute_hashes(Context* ctx);

inline static void destroy_ctx(Context* ctx);

void sha256_hash(const char* message, char* buffer);

#endif