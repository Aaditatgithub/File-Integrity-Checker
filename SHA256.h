#ifndef SHA256_H
#define SHA256_H

#include <cstdio>
#include <cstdint>
#include <cstring>

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SHR(x, n) ((x) >> (n))

const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


const uint32_t H[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};


#define CH(x, y, z) (((x) & (y)) ^ ((~x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EP1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define SIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

void sha256_transform(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h, t1, t2;

    // Prepare the message schedule
    for (int t = 0; t < 16; ++t) {
        W[t] = (block[t * 4] << 24) | (block[t * 4 + 1] << 16) |
            (block[t * 4 + 2] << 8) | (block[t * 4 + 3]);
    }
    for (int t = 16; t < 64; ++t) {
        W[t] = SIG1(W[t - 2]) + W[t - 7] + SIG0(W[t - 15]) + W[t - 16];
    }

    // Initialize working variables
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    // Main loop
    for (int t = 0; t < 64; ++t) {
        t1 = h + EP1(e) + CH(e, f, g) + K[t] + W[t];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    // Update the state with the computed values
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void sha256_init(uint32_t hash[8]) {
    memcpy(hash, H, sizeof(H));
}

void sha256_update(uint32_t hash[8], const uint8_t* message, size_t message_length) {
    size_t i;
    for (i = 0; i < message_length / 64; ++i) {
        sha256_transform(hash, message + i * 64);
    }

    // Handle the remaining partial block
    uint8_t last_block[64];
    size_t remaining_bytes = message_length - i * 64;
    memcpy(last_block, message + i * 64, remaining_bytes);

    // Padding
    last_block[remaining_bytes] = 0x80;
    if (remaining_bytes < 56) {
        memset(last_block + remaining_bytes + 1, 0, 56 - remaining_bytes - 1);
        *((uint64_t*)(last_block + 56)) = (message_length * 8);
        sha256_transform(hash, last_block);
    }
    else {
        memset(last_block + remaining_bytes + 1, 0, 64 - remaining_bytes - 1);
        sha256_transform(hash, last_block);
        memset(last_block, 0, 56);
        *((uint64_t*)(last_block + 56)) = (message_length * 8);
        sha256_transform(hash, last_block);
    }
}


void sha256_final(uint32_t hash[8], uint8_t buffer[64], size_t remaining_length, size_t total_bits) {
    memset(buffer + remaining_length, 0, 64 - remaining_length);

    // Add the padding bit
    buffer[remaining_length] = 0x80;

    if (remaining_length >= 56) {
        sha256_transform(hash, buffer);
        memset(buffer, 0, 64);
    }

    // Add the total length of the message in bits as big-endian
    uint64_t total_bits_big_endian = ((uint64_t)total_bits << 56) |
        ((uint64_t)total_bits << 48) |
        ((uint64_t)total_bits << 40) |
        ((uint64_t)total_bits << 32) |
        ((uint64_t)total_bits << 24) |
        ((uint64_t)total_bits << 16) |
        ((uint64_t)total_bits << 8) |
        ((uint64_t)total_bits);

    memcpy(buffer + 56, &total_bits_big_endian, sizeof(uint64_t));

    // Process the final block
    sha256_transform(hash, buffer);
}


void sha256(const uint8_t* message, size_t message_length, uint32_t hash[8]) {
    uint8_t buffer[64];  // Local buffer for padding and final block
    sha256_init(hash);
    sha256_update(hash, message, message_length);
    sha256_final(hash, buffer, message_length % 64, message_length * 8);
}

#endif // !SHA256_H

