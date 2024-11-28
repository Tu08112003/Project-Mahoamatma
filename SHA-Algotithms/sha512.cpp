#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

static int is_bigendian() {
    int i = 1;
    return *(char*)&i; // if returns 1 (big endian) else 0 (little endian).
}


#include "sha512.h"

sha512 SHA512();
void sha512_init(sha512* self);
void sha512_update(sha512* self, uint8_t* blocks, uint64_t blocks_len);
void sha512_digest(sha512* self, uint8_t* message, uint64_t message_len);
void sha512_core(uint8_t* blocks, size_t blocks_len, uint64_t digest[]);


#define h0 0x6a09e667f3bcc908
#define h1 0xbb67ae8584caa73b
#define h2 0x3c6ef372fe94f82b
#define h3 0xa54ff53a5f1d36f1
#define h4 0x510e527fade682d1
#define h5 0x9b05688c2b3e6c1f
#define h6 0x1f83d9abfb41bd6b
#define h7 0x5be0cd19137e2179

static uint64_t k[80] = {
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 
        0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 
        0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 
        0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 
        0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 
        0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 
        0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 
        0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 
        0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 
        0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 
        0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 
        0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 
        0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
    };

#define rotateleft(x, n) ((x << n) | (x >> (64 - n)))
#define rotateright(x, n) ((x >> n) | (x << (64 - n)))

#define u32_swap_endian(x) ( ((x >> 24) & 0xff) | ((x << 8) & 0xff0000) | ((x >> 8) & 0xff00) | ((x << 24) & 0xff000000) )
static uint64_t u64_swap_endian(uint64_t x) {
    x = (x & 0x00000000ffffffff) << 32 | (x & 0xffffffff00000000) >> 32;
    x = (x & 0x0000ffff0000ffff) << 16 | (x & 0xffff0000ffff0000) >> 16;
    x = (x & 0x00ff00ff00ff00ff) << 8  | (x & 0xff00ff00ff00ff00) >> 8;
    return x;
}

#define S0(a) (rotateright(a, 28) ^ rotateright(a, 34) ^ rotateright(a, 39))
#define S1(e) (rotateright(e, 14) ^ rotateright(e, 18) ^ rotateright(e, 41))


sha512 SHA512() {
    sha512 self;
    self.init = sha512_init;
    self.update = sha512_update;
    self.digest = sha512_digest;
    self.init(&self);
    return self; 
}

void sha512_init(sha512* self) { 
    self -> digests[0] = (uint64_t)h0;
    self -> digests[1] = (uint64_t)h1;
    self -> digests[2] = (uint64_t)h2;
    self -> digests[3] = (uint64_t)h3;
    self -> digests[4] = (uint64_t)h4;
    self -> digests[5] = (uint64_t)h5;
    self -> digests[6] = (uint64_t)h6;
    self -> digests[7] = (uint64_t)h7; 
    self -> len = 0; 
}

void sha512_update(sha512* self, uint8_t* blocks, uint64_t blocks_len) {

    if ((blocks_len % 128) == 0) {
        uint64_t digest[8];
        digest[0] = self -> digests[0];
        digest[1] = self -> digests[1];
        digest[2] = self -> digests[2];
        digest[3] = self -> digests[3];
        digest[4] = self -> digests[4];
        digest[5] = self -> digests[5];
        digest[6] = self -> digests[6];
        digest[7] = self -> digests[7];
        sha512_core(blocks, blocks_len, digest);
        self -> digests[0] = digest[0];
        self -> digests[1] = digest[1];
        self -> digests[2] = digest[2];
        self -> digests[3] = digest[3];
        self -> digests[4] = digest[4];
        self -> digests[5] = digest[5];
        self -> digests[6] = digest[6];
        self -> digests[7] = digest[7];
        self -> len += blocks_len;
    } else {
        printf("errr : at sha512() : sha512_update().\n");
    }
}

void sha512_digest(sha512* self, uint8_t* message, uint64_t message_len) {

    uint64_t digest[8];
    digest[0] = self -> digests[0];
    digest[1] = self -> digests[1];
    digest[2] = self -> digests[2];
    digest[3] = self -> digests[3];
    digest[4] = self -> digests[4];
    digest[5] = self -> digests[5];
    digest[6] = self -> digests[6];
    digest[7] = self -> digests[7];

    uint64_t padding_len = 128 - ((message_len + 16) % 128);
    (padding_len == 0) ? (padding_len = 128) : (padding_len = padding_len);

    uint64_t final_block_len;
    (padding_len <= 112) ? (final_block_len = 128) : (final_block_len = 256);
    
    uint64_t total_len = message_len + padding_len + 16;

    sha512_core(message, total_len - final_block_len, digest);

    size_t offset = message_len - (total_len - final_block_len);

    uint8_t final_block[256];
    for (size_t i = 0; i < offset; i++) {
        final_block[i] = *(uint8_t*)(message + (total_len - final_block_len) + i);
    }
    final_block[offset] = 0b10000000;
    for (size_t i = offset + 1; i < offset + padding_len + 8; i++) {
        final_block[i] = 0b00000000;
    }
    uint64_t message_len_in_bits = is_bigendian() == 1 ? u64_swap_endian((uint64_t)(message_len * 8)) : (uint64_t)(message_len * 8);
    memcpy(final_block + offset + padding_len + 8, &message_len_in_bits, 8);

    sha512_core(final_block, final_block_len, digest);
    
    self -> digests[0] = digest[0];
    self -> digests[1] = digest[1];
    self -> digests[2] = digest[2];
    self -> digests[3] = digest[3];
    self -> digests[4] = digest[4];
    self -> digests[5] = digest[5];
    self -> digests[6] = digest[6];
    self -> digests[7] = digest[7];
    self -> len += total_len;
}


void sha512_core(uint8_t* blocks, size_t blocks_len, uint64_t* digest) {
    
    uint64_t a, b, c, d, e, f, g, h;
    uint64_t s0, s1, ch, maj, temp1, temp2;
    uint64_t buffer[80];
    int endian = is_bigendian();
    
    for (size_t block = 0; block < blocks_len; block += 128) {

        if (endian == 1) {
            for (size_t i = 0; i < 16; i++) {
                buffer[i] = u64_swap_endian(*(uint64_t*)(blocks + block + (i * 8)));
            }
        } else {
            for (size_t i = 0; i < 16; i++) {
                buffer[i] = *(uint64_t*)(blocks + block + (i * 8));
            }
        }
        

        for (size_t i = 16; i < 80; i++) {
            s0 = (
                rotateright(buffer[i - 15], 1) ^
                rotateright(buffer[i - 15], 8) ^
                (buffer[i - 15] >> 7)
            );
            s1 = (
                rotateright(buffer[i - 2], 19) ^
                rotateright(buffer[i - 2], 61) ^
                (buffer[i - 2] >> 6)
            );
            buffer[i] = buffer[i - 16] + s0 + buffer[i - 7] + s1;
        }

        a = digest[0];
        b = digest[1];
        c = digest[2];
        d = digest[3];
        e = digest[4];
        f = digest[5];
        g = digest[6];
        h = digest[7];

        for (uint32_t i = 0; i < 80; i++) {
            // printf("%d %lx %lx %lx %lx \n   %lx %lx %lx %lx \n", i, a, b, c, d, e, f, g, h);
            ch = ((e & f) ^ ((~e) & g));
            temp1 = h + S1(e) + ch + k[i] + buffer[i];
            maj = ((a & b) ^ (a & c) ^ (b & c));
            temp2 = S0(a) + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;  
        }

        digest[0] += a;
        digest[1] += b;
        digest[2] += c;
        digest[3] += d;
        digest[4] += e;
        digest[5] += f;
        digest[6] += g;
        digest[7] += h;
    }
}

// uint64_t* sha512_digest_(uint8_t* message, size_t message_len, uint64_t digest[]) {

//     size_t padding_len = 128 - ((message_len + 16) % 128);
//     (padding_len == 0) ? (padding_len = 128) : (padding_len = padding_len);

//     size_t final_block_len;
//     (padding_len <= 112) ? (final_block_len = 128) : (final_block_len = 256);
    
//     size_t total_len = message_len + padding_len + 16;

//     uint64_t digest[8] = sha512_core(message, total_len - final_block_len, digest);

//     size_t offset = message_len - (total_len - final_block_len);

//     uint8_t final_block[256];
//     for (size_t i = 0; i < offset; i++) {
//         final_block[i] = *(uint8_t*)(message + (total_len - final_block_len) + i);
//     }
//     final_block[offset] = 0b10000000;
//     for (size_t i = offset + 1; i < offset + padding_len + 8; i++) {
//         final_block[i] = 0b00000000;
//     }
//     uint64_t message_len_in_bits = is_bigendian() == 1 ? u64_swap_endian((uint64_t)(message_len * 8)) : (uint64_t)(message_len * 8);
//     memcpy(final_block + offset + padding_len + 8, &message_len_in_bits, 8);

//     uint64_t digest[8] = sha512_core(final_block, final_block_len, digest);
//     return digest;
// }

