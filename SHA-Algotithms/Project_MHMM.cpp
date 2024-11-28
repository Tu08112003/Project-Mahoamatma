#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>


#define MAX_STRING_LENGTH 1024

void inputText(char *str) {
    printf("Nhap vao chuoi ma ban muon hash: ");
    fgets(str, sizeof(str), stdin);
    str[strcspn(str, "\n")] = '\0'; 
}

void outputText(const char *algorithm, const char *str) {
    printf("Chuoi ban vua nhap la: '%s'\n", str);
    printf("Ket qua bam bang thuat toan (%s) cua chuoi '%s' la: ", algorithm, str);

}

size_t readFile(const char *filePath, uint8_t **buffer) {
    FILE *file = fopen(filePath, "rb");
    if (!file) {
        printf("Khong the mo file: %s\n", filePath);
        return 0;
    }
    fseek(file, 0, SEEK_END);
    size_t fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    *buffer = (uint8_t *)malloc(fileSize);
    if (*buffer) {
        fread(*buffer, 1, fileSize, file);
    }
    fclose(file);

    return fileSize;
}

void inputFile(char *filePath) {
    printf("Nhap vao file ban muon hash: ");
    fgets(filePath, MAX_STRING_LENGTH, stdin);
    filePath[strcspn(filePath, "\n")] = '\0'; 
}

void outputFile(const char *algorithm , const char *filePath) {
    printf("File ban vua nhap la: '%s'\n", filePath);
    printf("Ket qua bam bang thuat toan (%s) cua file '%s' la: ", algorithm, filePath);
}


// SHA1

#include "sha1.h"
#define h0 0x67452301
#define h1 0xEFCDAB89
#define h2 0x98BADCFE
#define h3 0x10325476
#define h4 0xC3D2E1F0

#define rotateleft(x, n) ((x << n) | (x >> (32 - n)))

#define u32_swap_endian(x) ( ((x >> 24) & 0xff) | ((x << 8) & 0xff0000) | ((x >> 8) & 0xff00) | ((x << 24) & 0xff000000) )


static uint64_t u64_swap_endian(uint64_t x) {
    x = (x & 0x00000000ffffffff) << 32 | (x & 0xffffffff00000000) >> 32;
    x = (x & 0x0000ffff0000ffff) << 16 | (x & 0xffff0000ffff0000) >> 16;
    x = (x & 0x00ff00ff00ff00ff) << 8  | (x & 0xff00ff00ff00ff00) >> 8;
    return x;
}

uint32_t eighty_word_buffer(uint32_t* buffer, uint32_t index) {
    
    uint32_t word;
    
    switch(index / 16) {
        case 0:
            word = buffer[index];
            break;
        default:
            word = rotateleft(
                    (uint32_t)(
                            buffer[(index - 3) % 16] ^
                            buffer[(index - 8) % 16] ^
                            buffer[(index - 14) % 16] ^
                            buffer[(index - 16) % 16]
                        ),
                    1
                );
            buffer[(index - 16) % 16] = word;  
    }
    return word;
}


void sha1_core(uint8_t* blocks, size_t blocks_len, uint32_t digest[4]) {
    
    uint32_t a, b, c, d, e, f, k, temp;
    uint32_t buffer[16];
    
    for (size_t block = 0; block < blocks_len; block += 64) {
        
        a = digest[0];
        b = digest[1];
        c = digest[2];
        d = digest[3];
        e = digest[4];

        for (size_t i = 0; i < 16; i++) {
            buffer[i] = u32_swap_endian(*(uint32_t*)(blocks + block + (i * 4)));
        }

        for (uint32_t i = 0; i < 80; i++) {
            switch(i / 20) {
                case 0:
                    f = (b & c) ^ ((~b) & d);
                    k = 0x5A827999;
                    break;
                case 1:
                    f = (b ^ c ^ d);
                    k = 0x6ED9EBA1;
                    break;
                case 2:
                    f = (b & c) ^ (b & d) ^ (c & d);
                    k = 0x8F1BBCDC;
                    break;
                default:
                    f = b ^ c ^ d;
                    k = 0xCA62C1D6;
            }
            temp = rotateleft(a, 5) + f + e + k + eighty_word_buffer(buffer, i);
            e = d;
            d = c;
            c = rotateleft(b, 30);
            b = a;
            a = temp;
        }

        digest[0] += a;
        digest[1] += b;
        digest[2] += c;
        digest[3] += d;
        digest[4] += e;
    }
}

void sha1_digest(uint8_t* message, size_t message_len, uint32_t digest[5], bool debug) {

    size_t padding_len = 64 - ((message_len + 8) % 64);
    (padding_len == 0) ? (padding_len = 64) : (padding_len = padding_len);

    size_t final_block_len;
    (padding_len <= 56) ? (final_block_len = 64) : (final_block_len = 128);
    
    size_t total_len = message_len + padding_len + 8;

    if (debug == true) {
        printf("- (1/4) | total_len: %ld, message_len: %ld, padding_len: %ld, final_block_len: %ld \n", total_len, message_len, padding_len, final_block_len);
    }

    digest[0] = (uint32_t)h0;
    digest[1] = (uint32_t)h1;
    digest[2] = (uint32_t)h2;
    digest[3] = (uint32_t)h3;
    digest[4] = (uint32_t)h4;

    sha1_core(message, total_len - final_block_len, digest);

    if (debug == true) {
        printf("- (2/4) | md5_core() initial digest done.\n");
    }

    size_t offset = message_len - (total_len - final_block_len);

    uint8_t final_block[128];
    for (size_t i = 0; i < offset; i++) {
        final_block[i] = *(uint8_t*)(message + (total_len - final_block_len) + i);
    }
    final_block[offset] = 0b10000000;
    for (size_t i = offset + 1; i < offset + padding_len; i++) {
        final_block[i] = 0b00000000;
    }
    uint64_t message_len_in_bits = u64_swap_endian((uint64_t)(message_len * 8));
    memcpy(final_block + offset + padding_len, &message_len_in_bits, 8);

    if (debug == true) {
        printf("- (3/4) | md5 padding done.\n");
    }

    sha1_core(final_block, final_block_len, digest);
    if (debug == true) {
        printf("- (4/4) | md5_core() final digest done.\n");
    } 
}

// SHA224
#include "sha224.h"
#define h0_224 0xc1059ed8
#define h1_224 0x367cd507
#define h2_224 0x3070dd17
#define h3_224 0xf70e5939
#define h4_224 0xffc00b31
#define h5_224 0x68581511
#define h6_224 0x64f98fa7
#define h7_224 0xbefa4fa4

static uint32_t k[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };

#define rotateright(x, n) ((x >> n) | (x << (32 - n)))

void sha224_core(uint8_t* blocks, size_t blocks_len, uint32_t digest[]) {
    
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t s0, s1, S0, S1, ch, maj, temp1, temp2;
    uint32_t buffer[64];
    
    for (size_t block = 0; block < blocks_len; block += 64) {

        for (size_t i = 0; i < 16; i++) {
            buffer[i] = u32_swap_endian(*(uint32_t*)(blocks + block + (i * 4)));
        }

        for (size_t i = 16; i < 64; i++) {
            s0 = (
                rotateright(buffer[i - 15], 7) ^
                rotateright(buffer[i - 15], 18) ^
                (buffer[i - 15] >> 3)
            );
            s1 = (
                rotateright(buffer[i - 2], 17) ^
                rotateright(buffer[i - 2], 19) ^
                (buffer[i - 2] >> 10)
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

        for (uint32_t i = 0; i < 64; i++) {
            S1 = (rotateright(e, 6) ^ rotateright(e, 11) ^ rotateright(e, 25));
            ch = ((e & f) ^ ((~e) & g));
            temp1 = h + S1 + ch + k[i] + buffer[i];
            S0 = (rotateright(a, 2) ^ rotateright(a, 13) ^ rotateright(a, 22));
            maj = ((a & b) ^ (a & c) ^ (b & c));
            temp2 = S0 + maj;

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

void sha224_digest(uint8_t* message, size_t message_len, uint32_t digest[], bool debug) {

    size_t padding_len = 64 - ((message_len + 8) % 64);
    (padding_len == 0) ? (padding_len = 64) : (padding_len = padding_len);

    size_t final_block_len;
    (padding_len <= 56) ? (final_block_len = 64) : (final_block_len = 128);
    
    size_t total_len = message_len + padding_len + 8;

    if (debug == true) {
        printf("- (1/4) | total_len: %ld, message_len: %ld, padding_len: %ld, final_block_len: %ld \n", total_len, message_len, padding_len, final_block_len);
    }

    digest[0] = (uint32_t)h0_224;
    digest[1] = (uint32_t)h1_224;
    digest[2] = (uint32_t)h2_224;
    digest[3] = (uint32_t)h3_224;
    digest[4] = (uint32_t)h4_224;
    digest[5] = (uint32_t)h5_224;
    digest[6] = (uint32_t)h6_224;
    digest[7] = (uint32_t)h7_224;

    sha224_core(message, total_len - final_block_len, digest);

    if (debug == true) {
        printf("- (2/4) | md5_core() initial digest done.\n");
    }

    size_t offset = message_len - (total_len - final_block_len);

    uint8_t final_block[128];
    for (size_t i = 0; i < offset; i++) {
        final_block[i] = *(uint8_t*)(message + (total_len - final_block_len) + i);
    }
    final_block[offset] = 0b10000000;
    for (size_t i = offset + 1; i < offset + padding_len; i++) {
        final_block[i] = 0b00000000;
    }
    uint64_t message_len_in_bits = u64_swap_endian((uint64_t)(message_len * 8));
    memcpy(final_block + offset + padding_len, &message_len_in_bits, 8);

    if (debug == true) {
        printf("- (3/4) | md5 padding done.\n");
    }

    sha224_core(final_block, final_block_len, digest);
    if (debug == true) {
        printf("- (4/4) | md5_core() final digest done.\n");
    } 
}

//SHA256
#include "sha256.h"


#define h0_256 0x6a09e667
#define h1_256 0xbb67ae85
#define h2_256 0x3c6ef372
#define h3_256 0xa54ff53a
#define h4_256 0x510e527f
#define h5_256 0x9b05688c
#define h6_256 0x1f83d9ab
#define h7_256 0x5be0cd19

void sha256_core(uint8_t* blocks, size_t blocks_len, uint32_t digest[]) {
    
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t s0, s1, S0, S1, ch, maj, temp1, temp2;
    uint32_t buffer[64];
    
    for (size_t block = 0; block < blocks_len; block += 64) {

        for (size_t i = 0; i < 16; i++) {
            buffer[i] = u32_swap_endian(*(uint32_t*)(blocks + block + (i * 4)));
        }

        for (size_t i = 16; i < 64; i++) {
            s0 = (
                rotateright(buffer[i - 15], 7) ^
                rotateright(buffer[i - 15], 18) ^
                (buffer[i - 15] >> 3)
            );
            s1 = (
                rotateright(buffer[i - 2], 17) ^
                rotateright(buffer[i - 2], 19) ^
                (buffer[i - 2] >> 10)
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

        for (uint32_t i = 0; i < 64; i++) {
            S1 = (rotateright(e, 6) ^ rotateright(e, 11) ^ rotateright(e, 25));
            ch = ((e & f) ^ ((~e) & g));
            temp1 = h + S1 + ch + k[i] + buffer[i];
            S0 = (rotateright(a, 2) ^ rotateright(a, 13) ^ rotateright(a, 22));
            maj = ((a & b) ^ (a & c) ^ (b & c));
            temp2 = S0 + maj;

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

void sha256_digest(uint8_t* message, size_t message_len, uint32_t digest[], bool debug) {

    size_t padding_len = 64 - ((message_len + 8) % 64);
    (padding_len == 0) ? (padding_len = 64) : (padding_len = padding_len);

    size_t final_block_len;
    (padding_len <= 56) ? (final_block_len = 64) : (final_block_len = 128);
    
    size_t total_len = message_len + padding_len + 8;

    if (debug == true) {
        printf("- (1/4) | total_len: %ld, message_len: %ld, padding_len: %ld, final_block_len: %ld \n", total_len, message_len, padding_len, final_block_len);
    }

    digest[0] = (uint32_t)h0_256;
    digest[1] = (uint32_t)h1_256;
    digest[2] = (uint32_t)h2_256;
    digest[3] = (uint32_t)h3_256;
    digest[4] = (uint32_t)h4_256;
    digest[5] = (uint32_t)h5_256;
    digest[6] = (uint32_t)h6_256;
    digest[7] = (uint32_t)h7_256;

    sha256_core(message, total_len - final_block_len, digest);

    if (debug == true) {
        printf("- (2/4) | md5_core() initial digest done.\n");
    }

    size_t offset = message_len - (total_len - final_block_len);

    uint8_t final_block[128];
    for (size_t i = 0; i < offset; i++) {
        final_block[i] = *(uint8_t*)(message + (total_len - final_block_len) + i);
    }
    final_block[offset] = 0b10000000;
    for (size_t i = offset + 1; i < offset + padding_len; i++) {
        final_block[i] = 0b00000000;
    }
    uint64_t message_len_in_bits = u64_swap_endian((uint64_t)(message_len * 8));
    memcpy(final_block + offset + padding_len, &message_len_in_bits, 8);

    if (debug == true) {
        printf("- (3/4) | md5 padding done.\n");
    }

    sha256_core(final_block, final_block_len, digest);
    if (debug == true) {
        printf("- (4/4) | md5_core() final digest done.\n");
    } 
}
// SHA384

#define h0_384 0xcbbb9d5dc1059ed8
#define h1_384 0x629a292a367cd507
#define h2_384 0x9159015a3070dd17
#define h3_384 0x152fecd8f70e5939
#define h4_384 0x67332667ffc00b31
#define h5_384 0x8eb44a8768581511
#define h6_384 0xdb0c2e0d64f98fa7
#define h7_384 0x47b5481dbefa4fa4

static uint64_t k_64[80] = {
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

#define rotateleft_64(x, n) ((x << n) | (x >> (64 - n)))
#define rotateright_64(x, n) ((x >> n) | (x << (64 - n)))

#define S0(a) (rotateright_64(a, 28) ^ rotateright_64(a, 34) ^ rotateright_64(a, 39))
#define S1(e) (rotateright_64(e, 14) ^ rotateright_64(e, 18) ^ rotateright_64(e, 41))

void sha384_core(uint8_t* blocks, size_t blocks_len, uint64_t digest[]) {
    
    uint64_t a, b, c, d, e, f, g, h;
    uint64_t s0, s1, ch, maj, temp1, temp2;
    uint64_t buffer[80];
    
    for (size_t block = 0; block < blocks_len; block += 128) {

        for (size_t i = 0; i < 16; i++) {
            buffer[i] = u64_swap_endian(*(uint64_t*)(blocks + block + (i * 8)));
        }

        for (size_t i = 16; i < 80; i++) {
            s0 = (
                rotateright_64(buffer[i - 15], 1) ^
                rotateright_64(buffer[i - 15], 8) ^
                (buffer[i - 15] >> 7)
            );
            s1 = (
                rotateright_64(buffer[i - 2], 19) ^
                rotateright_64(buffer[i - 2], 61) ^
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
            temp1 = h + S1(e) + ch + k_64[i] + buffer[i];
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

void sha384_digest(uint8_t* message, size_t message_len, uint64_t digest[], bool debug) {

    size_t padding_len = 128 - ((message_len + 16) % 128);
    (padding_len == 0) ? (padding_len = 128) : (padding_len = padding_len);

    size_t final_block_len;
    (padding_len <= 112) ? (final_block_len = 128) : (final_block_len = 256);
    
    size_t total_len = message_len + padding_len + 16;

    if (debug == true) {
        printf("- (1/4) | total_len: %ld, message_len: %ld, padding_len: %ld, final_block_len: %ld \n", total_len, message_len, padding_len, final_block_len);
    }

    digest[0] = (uint64_t)h0_384;
    digest[1] = (uint64_t)h1_384;
    digest[2] = (uint64_t)h2_384;
    digest[3] = (uint64_t)h3_384;
    digest[4] = (uint64_t)h4_384;
    digest[5] = (uint64_t)h5_384;
    digest[6] = (uint64_t)h6_384;
    digest[7] = (uint64_t)h7_384;

    sha384_core(message, total_len - final_block_len, digest);

    if (debug == true) {
        printf("- (2/4) | md5_core() initial digest done.\n");
    }

    size_t offset = message_len - (total_len - final_block_len);

    uint8_t final_block[256];
    for (size_t i = 0; i < offset; i++) {
        final_block[i] = *(uint8_t*)(message + (total_len - final_block_len) + i);
    }
    final_block[offset] = 0b10000000;
    for (size_t i = offset + 1; i < offset + padding_len + 8; i++) {
        final_block[i] = 0b00000000;
    }
    uint64_t message_len_in_bits = u64_swap_endian((uint64_t)(message_len * 8));
    memcpy(final_block + offset + padding_len + 8, &message_len_in_bits, 8);

    // for (int i = 0; i < 256; i++) {
    //     printf("%x", final_block[i]);
    // }
    // printf("\n");

    if (debug == true) {
        printf("- (3/4) | md5 padding done.\n");
    }

    sha384_core(final_block, final_block_len, digest);
    if (debug == true) {
        printf("- (4/4) | md5_core() final digest done.\n");
    } 
}
// SHA512

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


#define h0_512 0x6a09e667f3bcc908
#define h1_512 0xbb67ae8584caa73b
#define h2_512 0x3c6ef372fe94f82b
#define h3_512 0xa54ff53a5f1d36f1
#define h4_512 0x510e527fade682d1
#define h5_512 0x9b05688c2b3e6c1f
#define h6_512 0x1f83d9abfb41bd6b
#define h7_512 0x5be0cd19137e2179

sha512 SHA512() {
    sha512 self;
    self.init = sha512_init;
    self.update = sha512_update;
    self.digest = sha512_digest;
    self.init(&self);
    return self; 
}

void sha512_init(sha512* self) { 
    self -> digests[0] = (uint64_t)h0_512;
    self -> digests[1] = (uint64_t)h1_512;
    self -> digests[2] = (uint64_t)h2_512;
    self -> digests[3] = (uint64_t)h3_512;
    self -> digests[4] = (uint64_t)h4_512;
    self -> digests[5] = (uint64_t)h5_512;
    self -> digests[6] = (uint64_t)h6_512;
    self -> digests[7] = (uint64_t)h7_512; 
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
                rotateright_64(buffer[i - 15], 1) ^
                rotateright_64(buffer[i - 15], 8) ^
                (buffer[i - 15] >> 7)
            );
            s1 = (
                rotateright_64(buffer[i - 2], 19) ^
                rotateright_64(buffer[i - 2], 61) ^
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
            temp1 = h + S1(e) + ch + k_64[i] + buffer[i];
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

//SHA512-224

#define h0_512_224 0x8C3D37C819544DA2
#define h1_512_224 0x73E1996689DCD4D6
#define h2_512_224 0x1DFAB7AE32FF9C82
#define h3_512_224 0x679DD514582F9FCF
#define h4_512_224 0x0F6D2B697BD44DA8
#define h5_512_224 0x77E36F7304C48942
#define h6_512_224 0x3F9D85A86A1D36C8
#define h7_512_224 0x1112E6AD91D692A1

void sha512_224_core(uint8_t* blocks, size_t blocks_len, uint64_t digest[]) {
    
    uint64_t a, b, c, d, e, f, g, h;
    uint64_t s0, s1, ch, maj, temp1, temp2;
    uint64_t buffer[80];
    
    for (size_t block = 0; block < blocks_len; block += 128) {

        for (size_t i = 0; i < 16; i++) {
            buffer[i] = u64_swap_endian(*(uint64_t*)(blocks + block + (i * 8)));
        }

        for (size_t i = 16; i < 80; i++) {
            s0 = (
                rotateright_64(buffer[i - 15], 1) ^
                rotateright_64(buffer[i - 15], 8) ^
                (buffer[i - 15] >> 7)
            );
            s1 = (
                rotateright_64(buffer[i - 2], 19) ^
                rotateright_64(buffer[i - 2], 61) ^
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
            temp1 = h + S1(e) + ch + k_64[i] + buffer[i];
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

void sha512_224_digest(uint8_t* message, size_t message_len, uint64_t digest[], bool debug) {

    size_t padding_len = 128 - ((message_len + 16) % 128);
    (padding_len == 0) ? (padding_len = 128) : (padding_len = padding_len);

    size_t final_block_len;
    (padding_len <= 112) ? (final_block_len = 128) : (final_block_len = 256);
    
    size_t total_len = message_len + padding_len + 16;

    if (debug == true) {
        printf("- (1/4) | total_len: %ld, message_len: %ld, padding_len: %ld, final_block_len: %ld \n", total_len, message_len, padding_len, final_block_len);
    }

    digest[0] = (uint64_t)h0_512_224;
    digest[1] = (uint64_t)h1_512_224;
    digest[2] = (uint64_t)h2_512_224;
    digest[3] = (uint64_t)h3_512_224;
    digest[4] = (uint64_t)h4_512_224;
    digest[5] = (uint64_t)h5_512_224;
    digest[6] = (uint64_t)h6_512_224;
    digest[7] = (uint64_t)h7_512_224;

    sha512_224_core(message, total_len - final_block_len, digest);

    if (debug == true) {
        printf("- (2/4) | md5_core() initial digest done.\n");
    }

    size_t offset = message_len - (total_len - final_block_len);

    uint8_t final_block[256];
    for (size_t i = 0; i < offset; i++) {
        final_block[i] = *(uint8_t*)(message + (total_len - final_block_len) + i);
    }
    final_block[offset] = 0b10000000;
    for (size_t i = offset + 1; i < offset + padding_len + 8; i++) {
        final_block[i] = 0b00000000;
    }
    uint64_t message_len_in_bits = u64_swap_endian((uint64_t)(message_len * 8));
    memcpy(final_block + offset + padding_len + 8, &message_len_in_bits, 8);

    // for (int i = 0; i < 256; i++) {
    //     printf("%x", final_block[i]);
    // }
    // printf("\n");

    if (debug == true) {
        printf("- (3/4) | md5 padding done.\n");
    }

    sha512_224_core(final_block, final_block_len, digest);
    if (debug == true) {
        printf("- (4/4) | md5_core() final digest done.\n");
    } 
}

//SHA512-256


#define h0_512_256 0x22312194FC2BF72C
#define h1_512_256 0x9F555FA3C84C64C2
#define h2_512_256 0x2393B86B6F53B151
#define h3_512_256 0x963877195940EABD
#define h4_512_256 0x96283EE2A88EFFE3
#define h5_512_256 0xBE5E1E2553863992
#define h6_512_256 0x2B0199FC2C85B8AA
#define h7_512_256 0x0EB72DDC81C52CA2

void sha512_256_core(uint8_t* blocks, size_t blocks_len, uint64_t digest[]) {
    
    uint64_t a, b, c, d, e, f, g, h;
    uint64_t s0, s1, ch, maj, temp1, temp2;
    uint64_t buffer[80];
    
    for (size_t block = 0; block < blocks_len; block += 128) {

        for (size_t i = 0; i < 16; i++) {
            buffer[i] = u64_swap_endian(*(uint64_t*)(blocks + block + (i * 8)));
        }

        for (size_t i = 16; i < 80; i++) {
            s0 = (
                rotateright_64(buffer[i - 15], 1) ^
                rotateright_64(buffer[i - 15], 8) ^
                (buffer[i - 15] >> 7)
            );
            s1 = (
                rotateright_64(buffer[i - 2], 19) ^
                rotateright_64(buffer[i - 2], 61) ^
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
            temp1 = h + S1(e) + ch + k_64[i] + buffer[i];
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

void sha512_256_digest(uint8_t* message, size_t message_len, uint64_t digest[], bool debug) {

    size_t padding_len = 128 - ((message_len + 16) % 128);
    (padding_len == 0) ? (padding_len = 128) : (padding_len = padding_len);

    size_t final_block_len;
    (padding_len <= 112) ? (final_block_len = 128) : (final_block_len = 256);
    
    size_t total_len = message_len + padding_len + 16;

    if (debug == true) {
        printf("- (1/4) | total_len: %ld, message_len: %ld, padding_len: %ld, final_block_len: %ld \n", total_len, message_len, padding_len, final_block_len);
    }

    digest[0] = (uint64_t)h0_512_256;
    digest[1] = (uint64_t)h1_512_256;
    digest[2] = (uint64_t)h2_512_256;
    digest[3] = (uint64_t)h3_512_256;
    digest[4] = (uint64_t)h4_512_256;
    digest[5] = (uint64_t)h5_512_256;
    digest[6] = (uint64_t)h6_512_256;
    digest[7] = (uint64_t)h7_512_256;

    sha512_256_core(message, total_len - final_block_len, digest);

    if (debug == true) {
        printf("- (2/4) | md5_core() initial digest done.\n");
    }

    size_t offset = message_len - (total_len - final_block_len);

    uint8_t final_block[256];
    for (size_t i = 0; i < offset; i++) {
        final_block[i] = *(uint8_t*)(message + (total_len - final_block_len) + i);
    }
    final_block[offset] = 0b10000000;
    for (size_t i = offset + 1; i < offset + padding_len + 8; i++) {
        final_block[i] = 0b00000000;
    }
    uint64_t message_len_in_bits = u64_swap_endian((uint64_t)(message_len * 8));
    memcpy(final_block + offset + padding_len + 8, &message_len_in_bits, 8);

    // for (int i = 0; i < 256; i++) {
    //     printf("%x", final_block[i]);
    // }
    // printf("\n");

    if (debug == true) {
        printf("- (3/4) | md5 padding done.\n");
    }

    sha512_256_core(final_block, final_block_len, digest);
    if (debug == true) {
        printf("- (4/4) | md5_core() final digest done.\n");
    } 
}

int main() {
    int a, b, c;

    printf("%108s\n", " _______________________________________________________ ");
    printf("%108s\n", "|                 BAI TAP MA HOA VA MAT MA              |");
    printf("%108s\n", "|_______________________________________________________|");
    printf("%108s\n", "|     Giang vien huong dan: PGS.TS Nguyen Tan Khoi      |");
    printf("%108s\n", "| Sinh vien thuc hien:             MSSV          Nhom:  |");
    printf("%108s\n", "| 1. Tran Ngoc Thanh Long        102210169      21Nh12  |");
    printf("%108s\n", "| 2. Huynh Tu                    102210193      21Nh12  |");
    printf("%108s\n", "| 3. Nguyen Tuan                 102210194      21Nh12  |");
    printf("%108s\n\n", "|_______________________________________________________|");

    do {
        printf("%100s\n", " ______________________________________ ");
        printf("%100s\n", "|            BANG CONG VIEC            |");
        printf("%100s\n", "|______________________________________|");
        printf("%100s\n", "|  1. Du lieu dau vao la chuoi         |");
        printf("%100s\n", "|  2. Du lieu dau vao la file          |");
        printf("%100s\n", "|  3. Thoat.                           |");
        printf("%100s\n\n", "|______________________________________|");

        do {
            printf("Nhap vao cong viec ban muon thuc hien: ");
            scanf("%d", &a);
            if (a > 3) printf("Moi ban nhap lai cong viec tuong ung o bang \n");
        } while (a > 3);

        if (a == 1) {
            do {
                printf("%100s\n", " ______________________________________ ");
                printf("%100s\n", "|              Loai ma hoa             |");
                printf("%100s\n", "|______________________________________|");
                printf("%100s\n", "|  1. SHA-1                            |");
                printf("%100s\n", "|  2. SHA-224 (SHA-2)                  |");
                printf("%100s\n", "|  3. SHA-256 (SHA-2)                  |");
                printf("%100s\n", "|  4. SHA-348 (SHA-512)                |");
                printf("%100s\n", "|  5. SHA-512 (SHA-512)                |");
                printf("%100s\n", "|  6. SHA-512/224 (SHA-512)            |");
                printf("%100s\n", "|  7. SHA-512/256 (SHA-512)            |");
                printf("%100s\n", "|  8. Thoat.                           |");
                printf("%100s\n\n", "|______________________________________|");

                do {
                    printf("Nhap vao cong viec ban muon thuc hien: ");
                    scanf("%d", &b);
                    getchar();
                    if (b > 8) printf("Moi ban nhap lai cong viec tuong ung o bang \n");
                } while (b > 8);

				if(b == 1){
					char input[MAX_STRING_LENGTH];
					inputText(input);
					uint32_t digest[5];
				    sha1_digest((uint8_t*)input, strlen(input), digest, false);
					outputText("SHA-1",input);
				    for (int i = 0; i < 5; i++) {
					    printf("%08x", digest[i]);
					}
					printf("\n");
				}
				
				if(b == 2){
					char input[MAX_STRING_LENGTH];
					inputText(input);
					uint32_t digest[8];
				    sha224_digest((uint8_t*)input, strlen(input), digest, false);
					outputText("SHA-224",input);
				    for (int i = 0; i < 7; i++) {
					    printf("%08x", digest[i]);
					}
					    printf("\n");
				}
				
                if(b == 3){
					char input[MAX_STRING_LENGTH];
					inputText(input);
					uint32_t digest[8];
				    sha256_digest((uint8_t*)input, strlen(input), digest, false);
					outputText("SHA-256",input);
				    for (int i = 0; i < 8; i++) {
					    printf("%08x", digest[i]);
					}
					printf("\n");

				}
				
				if(b == 4){
					char input[MAX_STRING_LENGTH];
					inputText(input);
					uint64_t digest[6];
				    sha384_digest((uint8_t*)input, strlen(input), digest, false);
					outputText("SHA-384",input);
				    for (int i = 0; i < 6; i++) {
				        printf("%016llx", digest[i]); 
				    }
				    printf("\n");
				}
				
				if(b == 5){
					sha512 hash = SHA512();
					char input[MAX_STRING_LENGTH];
					inputText(input);
					hash.digest(&hash, (uint8_t*)input, strlen(input));
					outputText("SHA-512",input);
					for (int i = 0; i < 8; i++) { 
				        printf("%016llx", hash.digests[i]); 
				    }
				    printf("\n");
				}
				
				if (b == 6) {
				    char input[MAX_STRING_LENGTH];
				    inputText(input);
				    uint64_t digest[4];
				    sha512_224_digest((uint8_t *)input, strlen(input), digest, false);
					outputText("SHA-512/224",input);
				
				    for (int i = 0; i < 3; i++) { 
				        printf("%016llx", digest[i]);
				    }
				    printf("\n");
				}

				
				if (b == 7) { 
				    char input[MAX_STRING_LENGTH];
				    inputText(input);
				    uint64_t digest[8];
				    sha512_256_digest((uint8_t *)input, strlen(input), digest, false);
					outputText("SHA-512/256",input);
				
				    for (int i = 0; i < 4; i++) { 
				        printf("%016llx", digest[i]);
				    }
				    printf("\n");
				}


				
            } while (b != 8);
        }

        if (a == 2) {
            do {
                printf("%100s\n", " ______________________________________ ");
                printf("%100s\n", "|              Loai ma hoa             |");
                printf("%100s\n", "|______________________________________|");
                printf("%100s\n", "|  1. SHA-1                            |");
                printf("%100s\n", "|  2. SHA-224 (SHA-2)                  |");
                printf("%100s\n", "|  3. SHA-256 (SHA-2)                  |");
                printf("%100s\n", "|  4. SHA-348 (SHA-512)                |");
                printf("%100s\n", "|  5. SHA-512 (SHA-512)                |");
                printf("%100s\n", "|  6. SHA-512/224 (SHA-512)            |");
                printf("%100s\n", "|  7. SHA-512/256 (SHA-512)            |");
                printf("%100s\n", "|  8. Thoat.                           |");
                printf("%100s\n\n", "|______________________________________|");

                do {
                    printf("Nhap vao cong viec ban muon thuc hien: ");
                    scanf("%d", &c);
                    getchar();
                    if (c > 8) printf("Moi ban nhap lai cong viec tuong ung o bang \n");
                } while (c > 8);

				if(c == 1){
					char filePath[MAX_STRING_LENGTH];
					inputFile(filePath);

					uint8_t *fileBuffer = NULL;
				    size_t fileSize = readFile(filePath, &fileBuffer);
				    
				    if (fileSize > 0) {
				        uint32_t digest[5];
				        sha1_digest(fileBuffer, fileSize, digest, false);  
						outputFile("SHA-1",filePath);
				        for (int i = 0; i < 5; i++) {
						    printf("%08x", digest[i]);
						}
						printf("\n");
				        free(fileBuffer);  
				    }
				}
				if(c == 2){
					char filePath[MAX_STRING_LENGTH];
					inputFile(filePath);

					uint8_t *fileBuffer = NULL;
				    size_t fileSize = readFile(filePath, &fileBuffer);
				    
				    if (fileSize > 0) {
				        uint32_t digest[8];
				        sha224_digest(fileBuffer, fileSize, digest, false);  
						outputFile("SHA-224",filePath);
				        for (int i = 0; i < 7; i++) {
						    printf("%08x", digest[i]);
						}
						printf("\n");
				        free(fileBuffer);  
				    }
				}
				
				if(c == 3){
					char filePath[MAX_STRING_LENGTH];
					inputFile(filePath);

					uint8_t *fileBuffer = NULL;
				    size_t fileSize = readFile(filePath, &fileBuffer);
				    
				    if (fileSize > 0) {
				        uint32_t digest[8];
				        sha256_digest(fileBuffer, fileSize, digest, false);  
						outputFile("SHA-256",filePath);
				        for (int i = 0; i < 8; i++) {
						    printf("%08x", digest[i]);
						}
						printf("\n");
				        free(fileBuffer);  
				    }
				}
				
				if(c == 4){
					char filePath[MAX_STRING_LENGTH];
					inputFile(filePath);

					uint8_t *fileBuffer = NULL;
				    size_t fileSize = readFile(filePath, &fileBuffer);
				    
				    if (fileSize > 0) {
				        uint64_t digest[6];
				        sha384_digest(fileBuffer, fileSize, digest, false);  
						outputFile("SHA-384",filePath);
				        for (int i = 0; i < 6; i++) {
					        printf("%016llx", digest[i]); 
					    }
				    printf("\n");
				        free(fileBuffer);  
				    }
				}
				
				if(c == 5){
					sha512 hash = SHA512();
					char filePath[MAX_STRING_LENGTH];
					inputFile(filePath);

					uint8_t *fileBuffer = NULL;
				    size_t fileSize = readFile(filePath, &fileBuffer);
				    
				    if (fileSize > 0) {
				        hash.digest(&hash, (uint8_t*)filePath, fileSize);
						outputFile("SHA-512",filePath);
						for (int i = 0; i < 8; i++) { 
					        printf("%016llx", hash.digests[i]); 
					    }
					    printf("\n");
				        free(fileBuffer);  
				    }
				}
				
				if(c == 6){
					char filePath[MAX_STRING_LENGTH];
					inputFile(filePath);

					uint8_t *fileBuffer = NULL;
				    size_t fileSize = readFile(filePath, &fileBuffer);
				    
				    if (fileSize > 0) {
				        uint64_t digest[4];
				        sha512_224_digest(fileBuffer, fileSize, digest, false);  
						outputFile("SHA-512/224",filePath);
				        for (int i = 0; i < 3; i++) { 
					        printf("%016llx", digest[i]);
					    }
					    printf("\n");
				        free(fileBuffer);  
				    }
				}
				
				if(c == 7){
					char filePath[MAX_STRING_LENGTH];
					inputFile(filePath);

					uint8_t *fileBuffer = NULL;
				    size_t fileSize = readFile(filePath, &fileBuffer);
				    
				    if (fileSize > 0) {
				        uint64_t digest[8];
				        sha512_256_digest(fileBuffer, fileSize, digest, false);  
						outputFile("SHA-512/256",filePath);
				        for (int i = 0; i < 4; i++) { 
					        printf("%016llx", digest[i]);
					    }
					    printf("\n");
				        free(fileBuffer);  
				    }
				}

            } while (c != 8);
        }
    } while (a != 3);

    return 0;
}

