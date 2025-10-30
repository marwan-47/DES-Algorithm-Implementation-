#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

// Platform-specific includes
#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib") // Link against the bcrypt library
#else
#include <strings.h> // For strcasecmp on Unix-like systems
#include <fcntl.h>
#include <unistd.h>
#endif

/**
 * @brief Fills a buffer with cryptographically secure random bytes.
 *
 * @param buffer The buffer to fill.
 * @param size The number of bytes to generate.
 * @return 0 on success, -1 on failure.
 */
int get_crypto_random_bytes(uint8_t *buffer, size_t size) {
#ifdef _WIN32
    NTSTATUS status = BCryptGenRandom(NULL, buffer, size, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Error: BCryptGenRandom failed.\n");
        return -1;
    }
    return 0;
#else
    int urandom_fd = open("/dev/urandom", O_RDONLY);
    if (urandom_fd == -1) {
        perror("Error opening /dev/urandom");
        return -1;
    }
    ssize_t bytes_read = read(urandom_fd, buffer, size);
    close(urandom_fd);
    if (bytes_read != (ssize_t)size) {
        fprintf(stderr, "Error: Could not read enough random data.\n");
        return -1;
    }
    return 0;
#endif
}

/**
 * @brief Generates and saves a 64-bit (8-byte) DES master key.
 *
 * @param filename The name of the binary file to save the key to.
 * @return 0 on success, -1 on failure.
 */
int generate_des_key(const char *filename) {
    uint8_t key[8];
    if (get_crypto_random_bytes(key, sizeof(key)) != 0) {
        return -1;
    }

    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        perror("Error opening key file for writing");
        return -1;
    }

    if (fwrite(key, 1, sizeof(key), fp) != sizeof(key)) {
        fprintf(stderr, "Error: Failed to write key to file.\n");
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

/**
 * @brief Generates a plaintext binary file for testing DES encryption.
 *
 * @param filename The name of the binary file to create.
 * @param num_blocks The total number of 8-byte blocks to generate.
 * @return 0 on success, -1 on failure.
 */
int generate_des_test_file(const char *filename, size_t num_blocks) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        perror("Error opening plaintext file for writing");
        return -1;
    }

    uint8_t patterns[4][8] = {
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
        {0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55},
        {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA}
    };

    size_t written_blocks = 0;
    if (num_blocks > 0) {
        size_t patterns_to_write = (num_blocks < 4) ? num_blocks : 4;
        if (fwrite(patterns, 8, patterns_to_write, fp) != patterns_to_write) {
            goto write_error;
        }
        written_blocks = patterns_to_write;
    }

    size_t random_blocks = num_blocks - written_blocks;
    if (random_blocks > 0) {
        size_t total_random_bytes = random_blocks * 8;
        uint8_t *random_data = (uint8_t *)malloc(total_random_bytes);
        if (!random_data) {
            perror("Error allocating memory for random data");
            fclose(fp);
            return -1;
        }

        if (get_crypto_random_bytes(random_data, total_random_bytes) != 0) {
            free(random_data);
            fclose(fp);
            return -1;
        }
        
        if (fwrite(random_data, 1, total_random_bytes, fp) != total_random_bytes) {
            free(random_data);
            goto write_error;
        }
        free(random_data);
    }

    fclose(fp);
    return 0;

write_error:
    fprintf(stderr, "Error writing to plaintext file: %s\n", strerror(errno));
    fclose(fp);
    return -1;
}

void print_usage(const char* prog_name) {
    fprintf(stderr, "Usage: %s <plaintext_file> <key_file> <size> <unit>\n", prog_name);
    fprintf(stderr, "  <size>: The numeric value of the size.\n");
    fprintf(stderr, "  <unit>: The size unit. Case-insensitive. (B, KB, MB, GB)\n\n");
    fprintf(stderr, "Example: %s plaintext.bin master.key 128 KB\n", prog_name);
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        print_usage(argv[0]);
        return 1;
    }

    const char *plaintext_filename = argv[1];
    const char *key_filename = argv[2];
    char *endptr;
    long long size_val = strtoll(argv[3], &endptr, 10);
    const char *size_unit = argv[4];

    if (*endptr != '\0' || size_val <= 0) {
        fprintf(stderr, "Error: Invalid size value '%s'. Must be a positive integer.\n", argv[3]);
        return 1;
    }
    
    // Use strcasecmp on non-windows, _stricmp on windows
    #ifdef _WIN32
        #define strcasecmp _stricmp
    #endif

    uint64_t multiplier;
    if (strcasecmp(size_unit, "B") == 0) multiplier = 1;
    else if (strcasecmp(size_unit, "KB") == 0) multiplier = 1024;
    else if (strcasecmp(size_unit, "MB") == 0) multiplier = 1024ULL * 1024;
    else if (strcasecmp(size_unit, "GB") == 0) multiplier = 1024ULL * 1024 * 1024;
    else {
        fprintf(stderr, "Error: Invalid size unit '%s'. Use B, KB, MB, or GB.\n", size_unit);
        return 1;
    }

    uint64_t total_bytes = (uint64_t)size_val * multiplier;
    if (total_bytes % 8 != 0) {
        fprintf(stderr, "Error: Total size (%llu bytes) must be a multiple of 8.\n", (unsigned long long)total_bytes);
        return 1;
    }
    
    if (total_bytes > (uint64_t)-1) {
        fprintf(stderr, "Error: Requested file size is too large.\n");
        return 1;
    }

    size_t num_blocks = total_bytes / 8;

    printf("Generating 64-bit master key -> %s\n", key_filename);
    if (generate_des_key(key_filename) != 0) {
        fprintf(stderr, "Failed to generate master key.\n");
        return 1;
    }

    printf("Generating plaintext file -> %s (%lld %s, %zu blocks)\n", plaintext_filename, size_val, size_unit, num_blocks);
    if (generate_des_test_file(plaintext_filename, num_blocks) != 0) {
        fprintf(stderr, "Failed to generate plaintext file.\n");
        return 1;
    }

    printf("Successfully generated test data.\n");
    return 0;
}