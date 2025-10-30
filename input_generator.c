#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <size> <unit: B|KB|MB>\n", argv[0]);
        return 1;
    }

    size_t size = atoi(argv[1]);
    char *unit = argv[2];

    size_t bytes;
    if (strcmp(unit, "B") == 0) {
        bytes = size;
    } else if (strcmp(unit, "KB") == 0) {
        bytes = size * 1024;
    } else if (strcmp(unit, "MB") == 0) {
        bytes = size * 1024 * 1024;
    } else {
        fprintf(stderr, "Unit must be B, KB or MB\n");
        return 1;
    }

    size_t blocks = bytes / sizeof(uint64_t); // 8-byte blocks

    FILE *plain = fopen("plaintext", "wb");
    FILE *key = fopen("key", "wb");
    if (!plain || !key) return 1;

    srand((unsigned)time(NULL));

    // Generate plaintext blocks
    for (size_t i = 0; i < blocks; i++) {
        // Assemble 64 bits from multiple rand() calls to avoid lots of zero bytes
        uint64_t block = 0;
        for (int k = 0; k < 4; ++k) {
            block = (block << 16) | (uint64_t)(rand() & 0xFFFF);
        }
        block += i;
        fwrite(&block, sizeof(uint64_t), 1, plain);
    }

    // Generate one random 64-bit key
    uint64_t k = 0;
    for (int i = 0; i < 4; ++i) {
        k = (k<< 16) | (uint64_t)(rand() & 0xFFFF);
    }
    fwrite(&k, sizeof(uint64_t), 1, key);

    fclose(plain);
    fclose(key);

    printf("Generated %zu bytes of plaintext and one 64-bit key.\n", blocks * sizeof(uint64_t));
    return 0;
}
