#define _CRT_SECURE_NO_WARNINGS
#include"SHA256.h"


int main() {
    // Open the file
    FILE* file = fopen("oneFile.txt", "rb");
    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }

    // Compute the SHA-256 hash
    uint32_t hash[8];
    size_t read_bytes;
    uint8_t buffer[64];  // 512-bit buffer for reading the file

    sha256_init(hash);

    while ((read_bytes = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        sha256_update(hash, buffer, read_bytes);
    }

    sha256_final(hash, buffer, read_bytes, read_bytes * 8);

    // Close the file
    fclose(file);

    // Print the hash
    printf("SHA-256 Hash of the file:\n");
    for (int i = 0; i < 8; ++i) {
        printf("%08x", hash[i]);
    }
    printf("\n");

    return 0;
}
