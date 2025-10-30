#include <stdio.h>
#include <stdint.h>
#include <immintrin.h>
#include <string.h>
#include <stdlib.h>

#define IO_BUFFER_SIZE (256 * 1024) 


static uint64_t IP_LOOKUP[8][256];
static uint64_t FP_LOOKUP[8][256];
static uint64_t E_LOOKUP[4][256];
static uint32_t P_LOOKUP[4][256];
static uint32_t SP_LOOKUP[8][64];
static int tables_initialized = 0;

const int IP[64] = {
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6,
    64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7
};

const int FP[64] = {
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25
};

const int E[48] = {
    32,  1,  2,  3,  4,  5,
    4,  5,  6,  7,  8,  9,
    8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
};

const int P[32] = {
    16,  7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25
};

const int PC1[56] = {
    57, 49, 41, 33, 25, 17,  9,
    1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36, 
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4
};

const int PC2[48] = {
    14, 17, 11, 24,  1,  5,
    3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};

const int SHIFTS[16] = {
    1, 1, 2, 2, 2, 2, 2, 2,
    1, 2, 2, 2, 2, 2, 2, 1
};

const int S1[4][16] = {
    {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
    {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
    {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
    {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}
};

const int S2[4][16] = {
    {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
    {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
    {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
    {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}
};

const int S3[4][16] = {
    {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
    {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
    {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
    {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}
};

const int S4[4][16] = {
    {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
    {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
    {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
    {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}
};

const int S5[4][16] = {
    {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
    {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
    {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
    {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}
};

const int S6[4][16] = {
    {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
    {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
    {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
    {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}
};

const int S7[4][16] = {
    {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
    {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
    {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
    {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}
};

const int S8[4][16] = {
    {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
    {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
    {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
    {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
};

const int (*SBOXES[8])[16] = { S1, S2, S3, S4, S5, S6, S7, S8 };


void init_tables(void) {
    if (tables_initialized) return;
    
    for (int byte_pos = 0; byte_pos < 8; byte_pos++) {
        for (int byte_val = 0; byte_val < 256; byte_val++) {
            uint64_t result = 0;
            for (int bit = 0; bit < 8; bit++) {
                if (byte_val & (1 << (7 - bit))) {
                    int source_bit = byte_pos * 8 + bit + 1;
                    for (int i = 0; i < 64; i++) {
                        if (IP[i] == source_bit) {
                            result |= (1ULL << (63 - i));
                            break;
                        }
                    }
                }
            }
            IP_LOOKUP[byte_pos][byte_val] = result;
        }
    }
    
    for (int byte_pos = 0; byte_pos < 8; byte_pos++) {
        for (int byte_val = 0; byte_val < 256; byte_val++) {
            uint64_t result = 0;
            for (int bit = 0; bit < 8; bit++) {
                if (byte_val & (1 << (7 - bit))) {
                    int source_bit = byte_pos * 8 + bit + 1;
                    for (int i = 0; i < 64; i++) {
                        if (FP[i] == source_bit) {
                            result |= (1ULL << (63 - i));
                            break;
                        }
                    }
                }
            }
            FP_LOOKUP[byte_pos][byte_val] = result;
        }
    }
    
    for (int byte_pos = 0; byte_pos < 4; byte_pos++) {
        for (int byte_val = 0; byte_val < 256; byte_val++) {
            uint64_t result = 0;
            for (int bit = 0; bit < 8; bit++) {
                if (byte_val & (1 << (7 - bit))) {
                    int source_bit = byte_pos * 8 + bit + 1;
                    for (int i = 0; i < 48; i++) {
                        if (E[i] == source_bit) {
                            result |= (1ULL << (47 - i));
                        }
                    }
                }
            }
            E_LOOKUP[byte_pos][byte_val] = result;
        }
    }
    
    for (int byte_pos = 0; byte_pos < 4; byte_pos++) {
        for (int byte_val = 0; byte_val < 256; byte_val++) {
            uint32_t result = 0;
            for (int bit = 0; bit < 8; bit++) {
                if (byte_val & (1 << (7 - bit))) {
                    int source_bit = byte_pos * 8 + bit + 1;
                    for (int i = 0; i < 32; i++) {
                        if (P[i] == source_bit) {
                            result |= (1U << (31 - i));
                            break;
                        }
                    }
                }
            }
            P_LOOKUP[byte_pos][byte_val] = result;
        }
    }
    
    for (int s = 0; s < 8; s++) {
        for (int v = 0; v < 64; v++) {
            int six_bits = v & 0x3F;
            int row = ((six_bits & 0x20) >> 4) | (six_bits & 0x01);
            int col = (six_bits >> 1) & 0x0F;
            int s_val = SBOXES[s][row][col] & 0x0F;
            // place the 4-bit s_val into its pre-permutation 32-bit position
            uint32_t before_p = ((uint32_t)s_val) << (28 - 4 * s);
            // apply P permutation (using P_LOOKUP) to that single contribution
            uint8_t *bytes = (uint8_t*)&before_p;
            uint32_t permuted = P_LOOKUP[0][bytes[3]] ^ P_LOOKUP[1][bytes[2]] ^
                                P_LOOKUP[2][bytes[1]] ^ P_LOOKUP[3][bytes[0]];
            SP_LOOKUP[s][v] = permuted;
        }
    }

    tables_initialized = 1;
}

static inline uint64_t initial_permutation(uint64_t input) {
    uint8_t *bytes = (uint8_t*)&input;
    return IP_LOOKUP[0][bytes[7]] ^ IP_LOOKUP[1][bytes[6]] ^
           IP_LOOKUP[2][bytes[5]] ^ IP_LOOKUP[3][bytes[4]] ^
           IP_LOOKUP[4][bytes[3]] ^ IP_LOOKUP[5][bytes[2]] ^
           IP_LOOKUP[6][bytes[1]] ^ IP_LOOKUP[7][bytes[0]];
}

static inline uint64_t final_permutation(uint64_t input) {
    uint8_t *bytes = (uint8_t*)&input;
    return FP_LOOKUP[0][bytes[7]] ^ FP_LOOKUP[1][bytes[6]] ^
           FP_LOOKUP[2][bytes[5]] ^ FP_LOOKUP[3][bytes[4]] ^
           FP_LOOKUP[4][bytes[3]] ^ FP_LOOKUP[5][bytes[2]] ^
           FP_LOOKUP[6][bytes[1]] ^ FP_LOOKUP[7][bytes[0]];
}

static inline uint64_t expansion(uint32_t right_half) {
    uint8_t *bytes = (uint8_t*)&right_half;
    return E_LOOKUP[0][bytes[3]] ^ E_LOOKUP[1][bytes[2]] ^
           E_LOOKUP[2][bytes[1]] ^ E_LOOKUP[3][bytes[0]];
}

static inline uint32_t permutation_pbox(uint32_t input) {
    uint8_t *bytes = (uint8_t*)&input;
    return P_LOOKUP[0][bytes[3]] ^ P_LOOKUP[1][bytes[2]] ^
           P_LOOKUP[2][bytes[1]] ^ P_LOOKUP[3][bytes[0]];
}

uint64_t permute(uint64_t input, const int *table, int table_size, int input_size){
    uint64_t output = 0;
    for (int i = 0; i < table_size; i++) {
        int src_bit_index = input_size - table[i];  
        uint64_t bit = (input >> src_bit_index) & 1ULL;
        output = (output << 1) | bit;
    }
    return output;
}

static inline uint32_t left_rotate28(uint32_t value, int shift){
    value &= 0x0FFFFFFF; 
    return ((value << shift) | (value >> (28 - shift))) & 0x0FFFFFFF;
}

static inline uint32_t sbox_substitution(uint64_t input48){
    uint32_t output32 = 0;
    int six_bits, row, col, s_val;
    
    six_bits = (input48 >> 42) & 0x3F; 
    row = ((six_bits & 0x20) >> 4) | (six_bits & 0x01);
    col = (six_bits >> 1) & 0x0F;
    s_val = SBOXES[0][row][col];
    output32 = (s_val & 0x0F) << 28;
    
    six_bits = (input48 >> 36) & 0x3F; 
    row = ((six_bits & 0x20) >> 4) | (six_bits & 0x01);
    col = (six_bits >> 1) & 0x0F;
    s_val = SBOXES[1][row][col];
    output32 |= (s_val & 0x0F) << 24;
    
    six_bits = (input48 >> 30) & 0x3F; 
    row = ((six_bits & 0x20) >> 4) | (six_bits & 0x01);
    col = (six_bits >> 1) & 0x0F;
    s_val = SBOXES[2][row][col];
    output32 |= (s_val & 0x0F) << 20;
    
    six_bits = (input48 >> 24) & 0x3F; 
    row = ((six_bits & 0x20) >> 4) | (six_bits & 0x01);
    col = (six_bits >> 1) & 0x0F;
    s_val = SBOXES[3][row][col];
    output32 |= (s_val & 0x0F) << 16;
    
    six_bits = (input48 >> 18) & 0x3F; 
    row = ((six_bits & 0x20) >> 4) | (six_bits & 0x01);
    col = (six_bits >> 1) & 0x0F;
    s_val = SBOXES[4][row][col];
    output32 |= (s_val & 0x0F) << 12;
    
    six_bits = (input48 >> 12) & 0x3F; 
    row = ((six_bits & 0x20) >> 4) | (six_bits & 0x01);
    col = (six_bits >> 1) & 0x0F;
    s_val = SBOXES[5][row][col];
    output32 |= (s_val & 0x0F) << 8;
    
    six_bits = (input48 >> 6) & 0x3F; 
    row = ((six_bits & 0x20) >> 4) | (six_bits & 0x01);
    col = (six_bits >> 1) & 0x0F;
    s_val = SBOXES[6][row][col];
    output32 |= (s_val & 0x0F) << 4;
    
    six_bits = input48 & 0x3F; 
    row = ((six_bits & 0x20) >> 4) | (six_bits & 0x01);
    col = (six_bits >> 1) & 0x0F;
    s_val = SBOXES[7][row][col];
    output32 |= (s_val & 0x0F);

    return output32;
}

static inline uint32_t feistel(uint32_t right, uint64_t subkey){
    uint64_t expand = expansion(right);
    uint64_t x = expand ^ subkey;
    
    uint32_t out = 0;
    out  = SP_LOOKUP[0][(x >> 42) & 0x3F];
    out ^= SP_LOOKUP[1][(x >> 36) & 0x3F];
    out ^= SP_LOOKUP[2][(x >> 30) & 0x3F];
    out ^= SP_LOOKUP[3][(x >> 24) & 0x3F];
    out ^= SP_LOOKUP[4][(x >> 18) & 0x3F];
    out ^= SP_LOOKUP[5][(x >> 12) & 0x3F];
    out ^= SP_LOOKUP[6][(x >> 6) & 0x3F];
    out ^= SP_LOOKUP[7][x & 0x3F];
    return out;
}

void generate_subkeys(uint64_t key, uint64_t subkeys[16]){
    uint64_t pc1 = permute(key, PC1, 56, 64);
    uint32_t left = (pc1 >> 28) & 0x0FFFFFFF;
    uint32_t right = pc1 & 0x0FFFFFFF;

    for(int i = 0; i < 16; i++){
        left = left_rotate28(left, SHIFTS[i]);
        right = left_rotate28(right, SHIFTS[i]);
        uint64_t combined56 = ((uint64_t)left << 28) | right;
        subkeys[i] = permute(combined56, PC2, 48, 56);
    }
}

static inline void des_encrypt_block(uint64_t *block, uint64_t subkeys[16]){
    uint64_t data = initial_permutation(*block);

    uint32_t L = (data >> 32);
    uint32_t R = (data & 0xFFFFFFFF);

    uint32_t temp;
    temp = R; R = L ^ feistel(R, subkeys[0]); L = temp;
    temp = R; R = L ^ feistel(R, subkeys[1]); L = temp;
    temp = R; R = L ^ feistel(R, subkeys[2]); L = temp;
    temp = R; R = L ^ feistel(R, subkeys[3]); L = temp;
    temp = R; R = L ^ feistel(R, subkeys[4]); L = temp;
    temp = R; R = L ^ feistel(R, subkeys[5]); L = temp;
    temp = R; R = L ^ feistel(R, subkeys[6]); L = temp;
    temp = R; R = L ^ feistel(R, subkeys[7]); L = temp;
    temp = R; R = L ^ feistel(R, subkeys[8]); L = temp;
    temp = R; R = L ^ feistel(R, subkeys[9]); L = temp;
    temp = R; R = L ^ feistel(R, subkeys[10]); L = temp;
    temp = R; R = L ^ feistel(R, subkeys[11]); L = temp;
    temp = R; R = L ^ feistel(R, subkeys[12]); L = temp;
    temp = R; R = L ^ feistel(R, subkeys[13]); L = temp;
    temp = R; R = L ^ feistel(R, subkeys[14]); L = temp;
    temp = R; R = L ^ feistel(R, subkeys[15]); L = temp;

    data = ((uint64_t)R << 32) | L;
    *block = final_permutation(data);
}

static inline void des_decrypt_block(uint64_t *block, uint64_t subkeys[16]){
    uint64_t data = initial_permutation(*block);

    uint32_t L = (data >> 32);
    uint32_t R = (data & 0xFFFFFFFF);

    
    uint32_t temp;
    temp = R; R = L ^ feistel(R, subkeys[15]); L = temp;
    temp = R; R = L ^ feistel(R, subkeys[14]); L = temp;
    temp = R; R = L ^ feistel(R, subkeys[13]); L = temp;
    temp = R; R = L ^ feistel(R, subkeys[12]); L = temp;
    temp = R; R = L ^ feistel(R, subkeys[11]); L = temp;
    temp = R; R = L ^ feistel(R, subkeys[10]); L = temp;
    temp = R; R = L ^ feistel(R, subkeys[9]); L = temp;
    temp = R; R = L ^ feistel(R, subkeys[8]); L = temp;
    temp = R; R = L ^ feistel(R, subkeys[7]); L = temp;
    temp = R; R = L ^ feistel(R, subkeys[6]); L = temp;
    temp = R; R = L ^ feistel(R, subkeys[5]); L = temp;
    temp = R; R = L ^ feistel(R, subkeys[4]); L = temp;
    temp = R; R = L ^ feistel(R, subkeys[3]); L = temp;
    temp = R; R = L ^ feistel(R, subkeys[2]); L = temp;
    temp = R; R = L ^ feistel(R, subkeys[1]); L = temp;
    temp = R; R = L ^ feistel(R, subkeys[0]); L = temp;

    data = ((uint64_t)R << 32) | L;
    *block = final_permutation(data);
}


static int bitslice_process_stream(FILE *fin, FILE *fout, uint64_t subkeys[16], char mode);


int main(int argc, char **argv){
    if (argc != 5) {
        printf("Usage:\n");
        printf("  %s e key plaintext ciphertext\n", argv[0]);
        printf("  %s d key ciphertext plaintext\n", argv[0]);
        return 1;
    }

    init_tables();

    char mode = argv[1][0];         
    const char *key_filename = argv[2];
    const char *input_filename = argv[3];
    const char *output_filename = argv[4];

    FILE *fkey = fopen(key_filename, "rb");
    FILE *fin  = fopen(input_filename, "rb");
    FILE *fout = fopen(output_filename, "wb");

    if (!fkey || !fin || !fout) {
        printf("Error: could not open one of the files.\n");
        if (fkey) fclose(fkey);
        if (fin) fclose(fin);
        if (fout) fclose(fout);
        return 1;
    }

    uint64_t key = 0;
    fread(&key, sizeof(uint64_t), 1, fkey);
    fclose(fkey);

    uint64_t subkeys[16];
    key = __builtin_bswap64(key);
    generate_subkeys(key, subkeys);

    
    if (mode == 'b' || mode == 'B'){
        int rc = bitslice_process_stream(fin, fout, subkeys, mode);
        fclose(fin);
        fclose(fout);
        return rc;
    }

    uint8_t *inbuf = (uint8_t *)malloc(IO_BUFFER_SIZE + 64);
    uint8_t *outbuf = (uint8_t *)malloc(IO_BUFFER_SIZE + 64);

    if (!inbuf || !outbuf) {
        fprintf(stderr, "Error: failed to allocate I/O buffers\n");
        free(inbuf);
        free(outbuf);
        fclose(fin);
        fclose(fout);
        return 1;
    }

    size_t leftover = 0;
    size_t in_len;
    
    while ((in_len = fread(inbuf + leftover, 1, IO_BUFFER_SIZE - leftover, fin)) > 0) {
        in_len += leftover;
        size_t num_blocks = in_len / 8;
        
        
        for (size_t i = 0; i < num_blocks; i++) {
            uint64_t block;
            memcpy(&block, &inbuf[i * 8], 8);
            block = __builtin_bswap64(block);
            
            if (mode == 'e')
                des_encrypt_block(&block, subkeys);
            else
                des_decrypt_block(&block, subkeys);
            
            block = __builtin_bswap64(block);
            memcpy(&outbuf[i * 8], &block, 8);
        }
        
        fwrite(outbuf, 1, num_blocks * 8, fout);
        
        leftover = in_len - (num_blocks * 8);
        if (leftover > 0) {
            memmove(inbuf, inbuf + num_blocks * 8, leftover);
        }
    }
    
    if (leftover > 0) {
        uint8_t last_block[8] = {0};
        memcpy(last_block, inbuf, leftover);
        
        uint64_t block;
        memcpy(&block, last_block, 8);
        block = __builtin_bswap64(block);
        
        if (mode == 'e')
            des_encrypt_block(&block, subkeys);
        else
            des_decrypt_block(&block, subkeys);
        
        block = __builtin_bswap64(block);
        fwrite(&block, 1, 8, fout);
    }

    free(inbuf);
    free(outbuf);
    fclose(fin);
    fclose(fout);
    return 0;
}

static void prepare_subkey_bitplanes(uint64_t subkeys[16], uint64_t subkey_bits[16][48]){
    for (int r = 0; r < 16; r++){
        for (int i = 0; i < 48; i++){
            int bit = (subkeys[r] >> (47 - i)) & 1ULL;
            subkey_bits[r][i] = bit ? ~0ULL : 0ULL;
        }
    }
}

static void bitsliced_sbox(const int sbox_index, uint64_t in6[6], uint64_t out4[4]){
    out4[0] = out4[1] = out4[2] = out4[3] = 0ULL;

    for (int p = 0; p < 64; p++){
        uint64_t m = ~0ULL;
        for (int k = 0; k < 6; k++){
            int bit = (p >> (5 - k)) & 1;
            m &= bit ? in6[k] : ~in6[k];
        }
        if (!m) continue;
        int row = ((p & 0x20) >> 4) | (p & 0x01);
        int col = (p >> 1) & 0x0F;
        int sval = SBOXES[sbox_index][row][col] & 0x0F;
        
        for (int t = 0; t < 4; t++){
            if ((sval >> t) & 1) {
                out4[t] |= m;
            }
        }
    }
}

static int bitslice_process_stream(FILE *fin, FILE *fout, uint64_t subkeys[16], char mode){
    const size_t BLOCKS = 64;
    uint8_t inbuf[BLOCKS * 8];
    uint8_t outbuf[BLOCKS * 8];
    uint64_t subkey_bits[16][48];
    prepare_subkey_bitplanes(subkeys, subkey_bits);

    while (1) {
        size_t read = fread(inbuf, 1, sizeof(inbuf), fin);
        if (read == 0) break;
        size_t blocks = read / 8;
        size_t processed = 0;

        while (blocks - processed >= BLOCKS) {
            uint64_t blocks64[BLOCKS];
            for (size_t i = 0; i < BLOCKS; i++){
                uint64_t tmp; memcpy(&tmp, inbuf + (processed + i) * 8, 8);
                tmp = __builtin_bswap64(tmp);
                blocks64[i] = initial_permutation(tmp);
            }

            uint64_t L_bits[32];
            uint64_t R_bits[32];
            for (int j = 0; j < 32; j++){ L_bits[j] = R_bits[j] = 0ULL; }

            for (size_t i = 0; i < BLOCKS; i++){
                uint64_t d = blocks64[i];
                uint32_t L = (uint32_t)(d >> 32);
                uint32_t R = (uint32_t)(d & 0xFFFFFFFF);
                for (int b = 0; b < 32; b++){
                    if ((L >> (31 - b)) & 1U) L_bits[b] |= (1ULL << i);
                    if ((R >> (31 - b)) & 1U) R_bits[b] |= (1ULL << i);
                }
            }

            for (int r = 0; r < 16; r++){

                uint64_t E_bits[48];
                for (int i = 0; i < 48; i++){
                    int src = E[i] - 1; 
                    E_bits[i] = R_bits[src];
                }

                for (int i = 0; i < 48; i++) E_bits[i] ^= subkey_bits[r][i];

                uint64_t s_out[32]; for (int i=0;i<32;i++) s_out[i]=0ULL;
                for (int s = 0; s < 8; s++){
                    uint64_t in6[6];
                    for (int k = 0; k < 6; k++) in6[k] = E_bits[6*s + k];
                    uint64_t out4[4]; out4[0]=out4[1]=out4[2]=out4[3]=0ULL;
                    bitsliced_sbox(s, in6, out4);
                    for (int t = 0; t < 4; t++){
                        int dst = 4*s + (3 - t);
                        s_out[dst] = out4[t];
                    }
                }

                uint64_t permuted[32];
                for (int i = 0; i < 32; i++){
                    permuted[i] = s_out[P[i] - 1];
                }

                uint64_t newL[32];
                uint64_t newR[32];
                for (int i = 0; i < 32; i++){
                    newL[i] = R_bits[i];
                    newR[i] = L_bits[i] ^ permuted[i];
                }
                for (int i = 0; i < 32; i++){ L_bits[i] = newL[i]; R_bits[i] = newR[i]; }
            }

            for (size_t i = 0; i < BLOCKS; i++){
                uint32_t L = 0, R = 0;
                for (int b = 0; b < 32; b++){
                    if ((L_bits[b] >> i) & 1ULL) L |= (1U << (31 - b));
                    if ((R_bits[b] >> i) & 1ULL) R |= (1U << (31 - b));
                }
                uint64_t data = ((uint64_t)R << 32) | L;
                data = final_permutation(data);
                uint64_t outv = __builtin_bswap64(data);
                memcpy(outbuf + i*8, &outv, 8);
            }

            fwrite(outbuf, 1, BLOCKS * 8, fout);
            processed += BLOCKS;
        }

        for (size_t i = 0; i < blocks - processed; i++){
            uint64_t block; memcpy(&block, inbuf + (processed + i) * 8, 8);
            block = __builtin_bswap64(block);
            if (mode == 'e') des_encrypt_block(&block, subkeys);
            else des_decrypt_block(&block, subkeys);
            block = __builtin_bswap64(block);
            memcpy(outbuf + i * 8, &block, 8);
        }
        fwrite(outbuf, 1, (blocks - processed) * 8, fout);

        size_t leftover = read - (blocks * 8);
        if (leftover) memmove((void*)inbuf, inbuf + blocks * 8, leftover);
        // seek back in file accordingly
        if (leftover) fseek(fin, -(long)leftover, SEEK_CUR);
    }
    return 0;
}



/*
$t = Measure-Command { .\des.exe e key.bin plain.bin cipher.bin }
    "enc time = {0:N3} sec" -f $t.TotalSeconds
    "enc throughput ≈ {0:N1} MiB/s" -f (64 / $t.TotalSeconds)
*/