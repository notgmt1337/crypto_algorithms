//License: GNU General Public License, Version 3
/*
 *   sha512.c - C Implementation of the SHA512 cryptographic algorithm
 *   
 *   Original author: George Tridimas <tridimasg@cardiff.ac.uk>
 */
#include "sha512.h"

#include <stdio.h>


static void init_ctx(Context* ctx, const char* message)
{
    ctx->message = message;
    ctx->length_in_bits = strlen(message) * 8;
    ctx->k = (895 - ctx->length_in_bits) % 1024; 
    ctx->padded_length_in_bits = ctx->length_in_bits + 1 + ctx->k + 128;
    ctx->padded = (uint8_t *) malloc(sizeof(uint8_t) * (ctx->padded_length_in_bits) / 8);
    ctx->hashes[0] = 0x6a09e667f3bcc908;
    ctx->hashes[1] = 0xbb67ae8584caa73b;
    ctx->hashes[2] = 0x3c6ef372fe94f82b;
    ctx->hashes[3] = 0xa54ff53a5f1d36f1;
    ctx->hashes[4] = 0x510e527fade682d1;
    ctx->hashes[5] = 0x9b05688c2b3e6c1f;
    ctx->hashes[6] = 0x1f83d9abfb41bd6b;
    ctx->hashes[7] = 0x5be0cd19137e2179;
}


static void pad_ctx(Context* ctx)
{
    uint128_t length = ctx->length_in_bits / 8;
    uint128_t padded_length = ctx->padded_length_in_bits / 8;

    for(uint128_t i = 0; i < length; i++)
    {
        *(ctx->padded + i) = ctx->message[i];
    }

    *(ctx->padded + length) = 128;

    for(uint128_t i = 0; i < (ctx->k - 7) / 8; i++)
    {
        *(ctx->padded + length + 1 + i) = 0;
    }

	*(ctx->padded + padded_length - 16) = (uint8_t) ((ctx->length_in_bits & mask(127)) >> 120); 	
	*(ctx->padded + padded_length - 15) = (uint8_t) ((ctx->length_in_bits & mask(119)) >> 112); 	
	*(ctx->padded + padded_length - 14) = (uint8_t) ((ctx->length_in_bits & mask(111)) >> 104); 	
	*(ctx->padded + padded_length - 13) = (uint8_t) ((ctx->length_in_bits & mask(103)) >> 96); 	
	*(ctx->padded + padded_length - 12) = (uint8_t) ((ctx->length_in_bits & mask(95)) >> 88); 	
	*(ctx->padded + padded_length - 11) = (uint8_t) ((ctx->length_in_bits & mask(87)) >> 80); 	
	*(ctx->padded + padded_length - 10) = (uint8_t) ((ctx->length_in_bits & mask(79)) >> 72); 	
	*(ctx->padded + padded_length - 9) = (uint8_t) ((ctx->length_in_bits & mask(71)) >> 64); 	
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
    uint128_t number_of_blocks = ctx->padded_length_in_bits / 1024;

    for(uint128_t i = 0; i < number_of_blocks; i++)
    {
        uint64_t W[80];
        
        W[0] = (((uint64_t) *(ctx->padded + 128 * i)) << 56)+ (((uint64_t) *(ctx->padded + 128 * i + 1)) << 48) + (((uint64_t) *(ctx->padded + 128 * i + 2)) << 40) + (((uint64_t) *(ctx->padded + 128 * i + 3)) << 32) + (((uint64_t) *(ctx->padded + 128 * i + 4)) << 24) + (((uint64_t) *(ctx->padded + 128 * i + 5)) << 16) + (((uint64_t) *(ctx->padded + 128 * i + 6)) << 8) + (((uint64_t) *(ctx->padded + 128 * i + 7)));
        W[1] = (((uint64_t) *(ctx->padded + 128 * i + 8)) << 56)+ (((uint64_t) *(ctx->padded + 128 * i + 9)) << 48) + (((uint64_t) *(ctx->padded + 128 * i + 10)) << 40) + (((uint64_t) *(ctx->padded + 128 * i + 11)) << 32) + (((uint64_t) *(ctx->padded + 128 * i + 12)) << 24) + (((uint64_t) *(ctx->padded + 128 * i + 13)) << 16) + (((uint64_t) *(ctx->padded + 128 * i + 14)) << 8) + (((uint64_t) *(ctx->padded + 128 * i + 15)));
        W[2] = (((uint64_t) *(ctx->padded + 128 * i + 16)) << 56)+ (((uint64_t) *(ctx->padded + 128 * i + 17)) << 48) + (((uint64_t) *(ctx->padded + 128 * i + 18)) << 40) + (((uint64_t) *(ctx->padded + 128 * i + 19)) << 32) + (((uint64_t) *(ctx->padded + 128 * i + 20)) << 24) + (((uint64_t) *(ctx->padded + 128 * i + 21)) << 16) + (((uint64_t) *(ctx->padded + 128 * i + 22)) << 8) + (((uint64_t) *(ctx->padded + 128 * i + 23)));
        W[3] = (((uint64_t) *(ctx->padded + 128 * i + 24)) << 56)+ (((uint64_t) *(ctx->padded + 128 * i + 25)) << 48) + (((uint64_t) *(ctx->padded + 128 * i + 26)) << 40) + (((uint64_t) *(ctx->padded + 128 * i + 27)) << 32) + (((uint64_t) *(ctx->padded + 128 * i + 28)) << 24) + (((uint64_t) *(ctx->padded + 128 * i + 29)) << 16) + (((uint64_t) *(ctx->padded + 128 * i + 30)) << 8) + (((uint64_t) *(ctx->padded + 128 * i + 31)));
        W[4] = (((uint64_t) *(ctx->padded + 128 * i + 32)) << 56)+ (((uint64_t) *(ctx->padded + 128 * i + 33)) << 48) + (((uint64_t) *(ctx->padded + 128 * i + 34)) << 40) + (((uint64_t) *(ctx->padded + 128 * i + 35)) << 32) + (((uint64_t) *(ctx->padded + 128 * i + 36)) << 24) + (((uint64_t) *(ctx->padded + 128 * i + 37)) << 16) + (((uint64_t) *(ctx->padded + 128 * i + 38)) << 8) + (((uint64_t) *(ctx->padded + 128 * i + 39)));
        W[5] = (((uint64_t) *(ctx->padded + 128 * i + 40)) << 56)+ (((uint64_t) *(ctx->padded + 128 * i + 41)) << 48) + (((uint64_t) *(ctx->padded + 128 * i + 42)) << 40) + (((uint64_t) *(ctx->padded + 128 * i + 43)) << 32) + (((uint64_t) *(ctx->padded + 128 * i + 44)) << 24) + (((uint64_t) *(ctx->padded + 128 * i + 45)) << 16) + (((uint64_t) *(ctx->padded + 128 * i + 46)) << 8) + (((uint64_t) *(ctx->padded + 128 * i + 47)));
        W[6] = (((uint64_t) *(ctx->padded + 128 * i + 48)) << 56)+ (((uint64_t) *(ctx->padded + 128 * i + 49)) << 48) + (((uint64_t) *(ctx->padded + 128 * i + 50)) << 40) + (((uint64_t) *(ctx->padded + 128 * i + 51)) << 32) + (((uint64_t) *(ctx->padded + 128 * i + 52)) << 24) + (((uint64_t) *(ctx->padded + 128 * i + 53)) << 16) + (((uint64_t) *(ctx->padded + 128 * i + 54)) << 8) + (((uint64_t) *(ctx->padded + 128 * i + 55)));
        W[7] = (((uint64_t) *(ctx->padded + 128 * i + 56)) << 56)+ (((uint64_t) *(ctx->padded + 128 * i + 57)) << 48) + (((uint64_t) *(ctx->padded + 128 * i + 58)) << 40) + (((uint64_t) *(ctx->padded + 128 * i + 59)) << 32) + (((uint64_t) *(ctx->padded + 128 * i + 60)) << 24) + (((uint64_t) *(ctx->padded + 128 * i + 61)) << 16) + (((uint64_t) *(ctx->padded + 128 * i + 62)) << 8) + (((uint64_t) *(ctx->padded + 128 * i + 63)));
        W[8] = (((uint64_t) *(ctx->padded + 128 * i + 64)) << 56)+ (((uint64_t) *(ctx->padded + 128 * i + 65)) << 48) + (((uint64_t) *(ctx->padded + 128 * i + 66)) << 40) + (((uint64_t) *(ctx->padded + 128 * i + 67)) << 32) + (((uint64_t) *(ctx->padded + 128 * i + 68)) << 24) + (((uint64_t) *(ctx->padded + 128 * i + 69)) << 16) + (((uint64_t) *(ctx->padded + 128 * i + 70)) << 8) + (((uint64_t) *(ctx->padded + 128 * i + 71)));
        W[9] = (((uint64_t) *(ctx->padded + 128 * i + 72)) << 56)+ (((uint64_t) *(ctx->padded + 128 * i + 73)) << 48) + (((uint64_t) *(ctx->padded + 128 * i + 74)) << 40) + (((uint64_t) *(ctx->padded + 128 * i + 75)) << 32) + (((uint64_t) *(ctx->padded + 128 * i + 76)) << 24) + (((uint64_t) *(ctx->padded + 128 * i + 77)) << 16) + (((uint64_t) *(ctx->padded + 128 * i + 78)) << 8) + (((uint64_t) *(ctx->padded + 128 * i + 79)));
        W[10] = (((uint64_t) *(ctx->padded + 128 * i + 80)) << 56)+ (((uint64_t) *(ctx->padded + 128 * i + 81)) << 48) + (((uint64_t) *(ctx->padded + 128 * i + 82)) << 40) + (((uint64_t) *(ctx->padded + 128 * i + 83)) << 32) + (((uint64_t) *(ctx->padded + 128 * i + 84)) << 24) + (((uint64_t) *(ctx->padded + 128 * i + 85)) << 16) + (((uint64_t) *(ctx->padded + 128 * i + 86)) << 8) + (((uint64_t) *(ctx->padded + 128 * i + 87)));
        W[11] = (((uint64_t) *(ctx->padded + 128 * i + 88)) << 56)+ (((uint64_t) *(ctx->padded + 128 * i + 89)) << 48) + (((uint64_t) *(ctx->padded + 128 * i + 90)) << 40) + (((uint64_t) *(ctx->padded + 128 * i + 91)) << 32) + (((uint64_t) *(ctx->padded + 128 * i + 92)) << 24) + (((uint64_t) *(ctx->padded + 128 * i + 93)) << 16) + (((uint64_t) *(ctx->padded + 128 * i + 94)) << 8) + (((uint64_t) *(ctx->padded + 128 * i + 95)));
        W[12] = (((uint64_t) *(ctx->padded + 128 * i + 96)) << 56)+ (((uint64_t) *(ctx->padded + 128 * i + 97)) << 48) + (((uint64_t) *(ctx->padded + 128 * i + 98)) << 40) + (((uint64_t) *(ctx->padded + 128 * i + 99)) << 32) + (((uint64_t) *(ctx->padded + 128 * i + 100)) << 24) + (((uint64_t) *(ctx->padded + 128 * i + 101)) << 16) + (((uint64_t) *(ctx->padded + 128 * i + 102)) << 8) + (((uint64_t) *(ctx->padded + 128 * i + 103)));
        W[13] = (((uint64_t) *(ctx->padded + 128 * i + 104)) << 56)+ (((uint64_t) *(ctx->padded + 128 * i + 105)) << 48) + (((uint64_t) *(ctx->padded + 128 * i + 106)) << 40) + (((uint64_t) *(ctx->padded + 128 * i + 107)) << 32) + (((uint64_t) *(ctx->padded + 128 * i + 108)) << 24) + (((uint64_t) *(ctx->padded + 128 * i + 109)) << 16) + (((uint64_t) *(ctx->padded + 128 * i + 110)) << 8) + (((uint64_t) *(ctx->padded + 128 * i + 111)));
        W[14] = (((uint64_t) *(ctx->padded + 128 * i + 112)) << 56)+ (((uint64_t) *(ctx->padded + 128 * i + 113)) << 48) + (((uint64_t) *(ctx->padded + 128 * i + 114)) << 40) + (((uint64_t) *(ctx->padded + 128 * i + 115)) << 32) + (((uint64_t) *(ctx->padded + 128 * i + 116)) << 24) + (((uint64_t) *(ctx->padded + 128 * i + 117)) << 16) + (((uint64_t) *(ctx->padded + 128 * i + 118)) << 8) + (((uint64_t) *(ctx->padded + 128 * i + 119)));
        W[15] = (((uint64_t) *(ctx->padded + 128 * i + 120)) << 56)+ (((uint64_t) *(ctx->padded + 128 * i + 121)) << 48) + (((uint64_t) *(ctx->padded + 128 * i + 122)) << 40) + (((uint64_t) *(ctx->padded + 128 * i + 123)) << 32) + (((uint64_t) *(ctx->padded + 128 * i + 124)) << 24) + (((uint64_t) *(ctx->padded + 128 * i + 125)) << 16) + (((uint64_t) *(ctx->padded + 128 * i + 126)) << 8) + (((uint64_t) *(ctx->padded + 128 * i + 127)));

        for(uint8_t r = 16; r <= 79; r++)
        {
            W[r] = s1(W[r-2]) + W[r-7] + s0(W[r-15]) + W[r-16];
        }

        uint64_t a = ctx->hashes[0];
        uint64_t b = ctx->hashes[1];
        uint64_t c = ctx->hashes[2];
        uint64_t d = ctx->hashes[3];
        uint64_t e = ctx->hashes[4];
        uint64_t f = ctx->hashes[5];
        uint64_t g = ctx->hashes[6];
        uint64_t h = ctx->hashes[7];

        for(uint8_t r = 0; r < 80; r++)
        {
		    uint64_t T1 = h + S1(e) + Ch(e, f, g) + K[r] + W[r];
		    uint64_t T2 = S0(a) + Maj(a, b, c);
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

void sha512_hash(const char* message, char* buffer)
{
    Context ctx;
    init_ctx(&ctx, message);
    pad_ctx(&ctx);
    compute_hashes(&ctx);
    
    char* digits = "0123456789abcdef";

    char* hash = (char *) malloc(sizeof(char) * 128);

    
    for(uint8_t i = 0; i < 8; i++)
    {

		uint8_t h1 = (uint8_t) ((ctx.hashes[i] & ((uint64_t) 15 << 60)) >> 60);
		uint8_t h2 = (uint8_t) ((ctx.hashes[i] & ((uint64_t) 15 << 56)) >> 56);
		uint8_t h3 = (uint8_t) ((ctx.hashes[i] & ((uint64_t) 15 << 52)) >> 52);
		uint8_t h4 = (uint8_t) ((ctx.hashes[i] & ((uint64_t) 15 << 48)) >> 48);
		uint8_t h5 = (uint8_t) ((ctx.hashes[i] & ((uint64_t) 15 << 44)) >> 44);
		uint8_t h6 = (uint8_t) ((ctx.hashes[i] & ((uint64_t) 15 << 40)) >> 40);
		uint8_t h7 = (uint8_t) ((ctx.hashes[i] & ((uint64_t) 15 << 36)) >> 36);
		uint8_t h8 = (uint8_t) ((ctx.hashes[i] & ((uint64_t) 15 << 32)) >> 32);
		uint8_t h9 = (uint8_t) ((ctx.hashes[i] & ((uint64_t) 15 << 28)) >> 28);
		uint8_t h10 = (uint8_t) ((ctx.hashes[i] & ((uint64_t) 15 << 24)) >> 24);
		uint8_t h11 = (uint8_t) ((ctx.hashes[i] & ((uint64_t) 15 << 20)) >> 20);
		uint8_t h12 = (uint8_t) ((ctx.hashes[i] & ((uint64_t) 15 << 16)) >> 16);
		uint8_t h13 = (uint8_t) ((ctx.hashes[i] & ((uint64_t) 15 << 12)) >> 12);
		uint8_t h14 = (uint8_t) ((ctx.hashes[i] & ((uint64_t) 15 << 8)) >> 8);
		uint8_t h15 = (uint8_t) ((ctx.hashes[i] & ((uint64_t) 15 << 4)) >> 4);
		uint8_t h16 = (uint8_t) ((ctx.hashes[i] & ((uint64_t) 15)));


		*(hash + 8 * i) = digits[h1];
		*(hash + 8 * i + 1) = digits[h2];
		*(hash + 8 * i + 2) = digits[h3];
		*(hash + 8 * i + 3) = digits[h4];
		*(hash + 8 * i + 4) = digits[h5];
		*(hash + 8 * i + 5) = digits[h6];
		*(hash + 8 * i + 6) = digits[h7];
		*(hash + 8 * i + 7) = digits[h8];
		*(hash + 8 * i + 8) = digits[h9];
		*(hash + 8 * i + 9) = digits[h10];
		*(hash + 8 * i + 10) = digits[h11];
		*(hash + 8 * i + 11) = digits[h12];
		*(hash + 8 * i + 12) = digits[h13];
		*(hash + 8 * i + 13) = digits[h14];
		*(hash + 8 * i + 14) = digits[h15];
		*(hash + 8 * i + 15) = digits[h16];
    }


    strcpy(buffer, hash);
    free(hash);
    destroy_ctx(&ctx);
}