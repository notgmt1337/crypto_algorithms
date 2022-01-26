//License: GNU General Public License, Version 3
/*
 *   sha256.c - C implementation of the SHA256 cryptographic hashing algorithm
 *   
 *   Original author: George Tridimas <tridimasg@cardiff.ac.uk>
 */
#include "sha256.h"

static void init_ctx(Context* ctx, const char* message)
{
	ctx->message = message;
	ctx->length_in_bits = strlen(message) * 8;
	ctx->k = (447 - ctx->length_in_bits) % 512;
	ctx->padded_length_in_bits = ctx->length_in_bits + 1 + ctx->k + 64;
	ctx->padded = (uint8_t *) malloc(sizeof(uint8_t) * (ctx->padded_length_in_bits)/8);
	ctx->hashes[0] = 0x6a09e667;
	ctx->hashes[1] = 0xbb67ae85;
	ctx->hashes[2] = 0x3c6ef372;
	ctx->hashes[3] = 0xa54ff53a;
	ctx->hashes[4] = 0x510e527f;
	ctx->hashes[5] = 0x9b05688c;
	ctx->hashes[6] = 0x1f83d9ab;
	ctx->hashes[7] = 0x5be0cd19;
}


static void pad_ctx(Context* ctx)
{
	uint64_t length = ctx->length_in_bits / 8;
	uint64_t padded_length = ctx->padded_length_in_bits / 8;

	for(size_t i = 0; i < length; i++)
	{
		*(ctx->padded + i) = ctx->message[i];
	}
	
	*(ctx->padded + length) = 128;

	for(size_t i = 0; i < (ctx->k - 7) / 8; i++)
	{
		*(ctx->padded + length + 1 + i) = 0;
	}


	
	*(ctx->padded + padded_length - 8) = (uint8_t) ((ctx->length_in_bits & mask(63)) >> 56); 	
	*(ctx->padded + padded_length - 7) = (uint8_t) ((ctx->length_in_bits & mask(55)) >> 48); 	
	*(ctx->padded + padded_length - 6) = (uint8_t) ((ctx->length_in_bits & mask(47)) >> 40); 	
	*(ctx->padded + padded_length - 5) = (uint8_t) ((ctx->length_in_bits & mask(39)) >> 32); 	
	*(ctx->padded + padded_length - 4) = (uint8_t) ((ctx->length_in_bits & mask(31)) >> 24); 	
	*(ctx->padded + padded_length - 3) = (uint8_t) ((ctx->length_in_bits & mask(23)) >> 16); 	
	*(ctx->padded + padded_length - 2) = (uint8_t) ((ctx->length_in_bits & mask(15)) >> 8); 	
	*(ctx->padded + padded_length - 1) = (uint8_t) ((ctx->length_in_bits & mask(7))); 	

}

static void compute_hashes(Context* ctx)
{
	uint64_t number_of_blocks = ctx->padded_length_in_bits / 512;

	for(uint64_t i = 0; i < number_of_blocks; i++)
	{
		uint32_t W[64];

		W[0] = (((uint32_t) *(ctx->padded + 64 * i)) << 24) | (((uint32_t) *(ctx->padded + 64 * i + 1)) << 16) | (((uint32_t) *(ctx->padded + 64 * i + 2)) << 8) | (((uint32_t) *(ctx->padded + 64 * i + 3)));
		W[1] = (((uint32_t) *(ctx->padded + 64 * i + 4)) << 24) | (((uint32_t) *(ctx->padded + 64 * i + 5)) << 16) | (((uint32_t) *(ctx->padded + 64 * i + 6)) << 8) | (((uint32_t) *(ctx->padded + 64 * i + 7)));
		W[2] = (((uint32_t) *(ctx->padded + 64 * i + 8)) << 24) | (((uint32_t) *(ctx->padded + 64 * i + 9)) << 16) | (((uint32_t) *(ctx->padded + 64 * i + 10)) << 8) | (((uint32_t) *(ctx->padded + 64 * i + 11)));
		W[3] = (((uint32_t) *(ctx->padded + 64 * i + 12)) << 24) | (((uint32_t) *(ctx->padded + 64 * i + 13)) << 16) | (((uint32_t) *(ctx->padded + 64 * i + 14)) << 8) | (((uint32_t) *(ctx->padded + 64 * i + 15)));
		W[4] = (((uint32_t) *(ctx->padded + 64 * i + 16)) << 24) | (((uint32_t) *(ctx->padded + 64 * i + 17)) << 16) | (((uint32_t) *(ctx->padded + 64 * i + 18)) << 8) | (((uint32_t) *(ctx->padded + 64 * i + 19)));
		W[5] = (((uint32_t) *(ctx->padded + 64 * i + 20)) << 24) | (((uint32_t) *(ctx->padded + 64 * i + 21)) << 16) | (((uint32_t) *(ctx->padded + 64 * i + 22)) << 8) | (((uint32_t) *(ctx->padded + 64 * i + 23)));
		W[6] = (((uint32_t) *(ctx->padded + 64 * i + 24)) << 24) | (((uint32_t) *(ctx->padded + 64 * i + 25)) << 16) | (((uint32_t) *(ctx->padded + 64 * i + 26)) << 8) | (((uint32_t) *(ctx->padded + 64 * i + 27)));
	    W[7] = (((uint32_t) *(ctx->padded + 64 * i + 28)) << 24) | (((uint32_t) *(ctx->padded + 64 * i + 29)) << 16) | (((uint32_t) *(ctx->padded + 64 * i + 30)) << 8) | (((uint32_t) *(ctx->padded + 64 * i + 31)));
		W[8] = (((uint32_t) *(ctx->padded + 64 * i + 32)) << 24) | (((uint32_t) *(ctx->padded + 64 * i + 33)) << 16) | (((uint32_t) *(ctx->padded + 64 * i + 34)) << 8) | (((uint32_t) *(ctx->padded + 64 * i + 35)));
		W[9] = (((uint32_t) *(ctx->padded + 64 * i + 36)) << 24) | (((uint32_t) *(ctx->padded + 64 * i + 37)) << 16) | (((uint32_t) *(ctx->padded + 64 * i + 38)) << 8) | (((uint32_t) *(ctx->padded + 64 * i + 39)));
		W[10] = (((uint32_t) *(ctx->padded + 64 * i + 40)) << 24) | (((uint32_t) *(ctx->padded + 64 * i + 41)) << 16) | (((uint32_t) *(ctx->padded + 64 * i + 42)) << 8) | (((uint32_t) *(ctx->padded + 64 * i + 43)));
		W[11] = (((uint32_t) *(ctx->padded + 64 * i + 44)) << 24) | (((uint32_t) *(ctx->padded + 64 * i + 45)) << 16) | (((uint32_t) *(ctx->padded + 64 * i + 46)) << 8) | (((uint32_t) *(ctx->padded + 64 * i + 47)));
		W[12] = (((uint32_t) *(ctx->padded + 64 * i + 48)) << 24) | (((uint32_t) *(ctx->padded + 64 * i + 49)) << 16) | (((uint32_t) *(ctx->padded + 64 * i + 50)) << 8) | (((uint32_t) *(ctx->padded + 64 * i + 51)));
		W[13] = (((uint32_t) *(ctx->padded + 64 * i + 52)) << 24) | (((uint32_t) *(ctx->padded + 64 * i + 53)) << 16) | (((uint32_t) *(ctx->padded + 64 * i + 54)) << 8) | (((uint32_t) *(ctx->padded + 64 * i + 55)));
		W[14] = (((uint32_t) *(ctx->padded + 64 * i + 56)) << 24) | (((uint32_t) *(ctx->padded + 64 * i + 57)) << 16) | (((uint32_t) *(ctx->padded + 64 * i + 58)) << 8) | (((uint32_t) *(ctx->padded + 64 * i + 59)));
	    W[15] = (((uint32_t) *(ctx->padded + 64 * i + 60)) << 24) | (((uint32_t) *(ctx->padded + 64 * i + 61)) << 16) | (((uint32_t) *(ctx->padded + 64 * i + 62)) << 8) | (((uint32_t) *(ctx->padded + 64 * i + 63)));

		for(uint8_t j = 16; j <= 63; j++)
		{
			W[j] = s1(W[j-2]) + W[j-7] + s0(W[j-15]) + W[j-16];
		}

		uint32_t a = ctx->hashes[0];
		uint32_t b = ctx->hashes[1];
		uint32_t c = ctx->hashes[2];
		uint32_t d = ctx->hashes[3];
		uint32_t e = ctx->hashes[4];
		uint32_t f = ctx->hashes[5];
		uint32_t g = ctx->hashes[6];
		uint32_t h = ctx->hashes[7];

		for(uint8_t r = 0; r < 64; r++)
		{
		   uint32_t T1 = h + S1(e) + Ch(e, f, g) + K[r] + W[r];
		   uint32_t T2 = S0(a) + Maj(a, b, c);
			h = g;
			g = f;
			f = e;
			e = d + T1;
			d = c;
			c = b;
			b = a;
			a = T1 + T2;
		}
		ctx->hashes[0] += a;
		ctx->hashes[1] += b;
		ctx->hashes[2] += c;
		ctx->hashes[3] += d;
		ctx->hashes[4] += e;
		ctx->hashes[5] += f;
		ctx->hashes[6] += g;
		ctx->hashes[7] += h;

	}

}

inline static void destroy_ctx(Context* ctx)
{
	free(ctx->padded);
}

void sha256_hash(const char* message, char* buffer)
{

	Context ctx;
	init_ctx(&ctx, message);
	pad_ctx(&ctx);
	compute_hashes(&ctx);

	char* digits = "0123456789abcdef";

	char* hash = (char *) malloc(sizeof(char) * 64);

	for(uint8_t i = 0; i < 8; i++)
	{
		uint8_t h1 = (uint8_t) ((ctx.hashes[i] & (15 << 28)) >> 28);
		uint8_t h2 = (uint8_t) ((ctx.hashes[i] & (15 << 24)) >> 24);
		uint8_t h3 = (uint8_t) ((ctx.hashes[i] & (15 << 20)) >> 20);
		uint8_t h4 = (uint8_t) ((ctx.hashes[i] & (15 << 16)) >> 16);
		uint8_t h5 = (uint8_t) ((ctx.hashes[i] & (15 << 12)) >> 12);
		uint8_t h6 = (uint8_t) ((ctx.hashes[i] & (15 << 8)) >> 8);
		uint8_t h7 = (uint8_t) ((ctx.hashes[i] & (15 << 4)) >> 4);
		uint8_t h8 = (uint8_t) ((ctx.hashes[i] & (15)));

		*(hash + 8 * i) = digits[h1];
		*(hash + 8 * i + 1) = digits[h2];
		*(hash + 8 * i + 2) = digits[h3];
		*(hash + 8 * i + 3) = digits[h4];
		*(hash + 8 * i + 4) = digits[h5];
		*(hash + 8 * i + 5) = digits[h6];
		*(hash + 8 * i + 6) = digits[h7];
		*(hash + 8 * i + 7) = digits[h8];
	}

	strcpy(buffer, hash);
	free(hash);
	destroy_ctx(&ctx);

}