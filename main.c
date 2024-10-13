#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define TF_ENCRYPT 1
#define TF_DECRYPT 0

typedef union {
    uint32_t w[4];
    uint8_t b[16];
} tf_blk;

typedef struct {
    uint32_t keys[40];
    uint8_t sbox[256 * 4];
    uint8_t qbox[4][256];
} tf_ctx;

typedef struct {
    uint32_t q[4];
} tf_key;

void whiten(tf_blk *in, uint32_t *keys) {
    for (int i = 0; i < 4; i++) {
        in->w[i] ^= keys[i];
    }
}

uint32_t mds(uint32_t w) {
    uint32_t matrix[4][4] = {
        {0x01, 0xEF, 0x5B, 0x5B},
        {0x5B, 0xEF, 0xEF, 0x01},
        {0xEF, 0x5B, 0x01, 0xEF},
        {0xEF, 0x01, 0xEF, 0x5B}}; 

    uint32_t acc = 0;
    uint8_t x[4] = { (uint8_t)(w >> 24), (uint8_t)(w >> 16), (uint8_t)(w >> 8), (uint8_t)w };

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            uint8_t x0 = matrix[i][j];
            uint8_t y = x[j];
            while (y) {
                if (x0 > (x0 ^ 0x169))
                    x0 ^= 0x169;
                if (y & 1)
                    acc ^= x0;
                x0 <<= 1;
                y >>= 1;
            }
        }
    }
    return acc;
}

uint32_t round_g(tf_ctx *ctx, uint32_t w) {
    uint32_t x = w;
    uint32_t result = 0;

    for (int i = 0; i < 4; i++) {
        x = ctx->sbox[x & 0xFF] ^ (x >> 8);
    }
    result = mds(x);
    return result;
}

void tf_enc(tf_ctx *ctx, tf_blk *data, int enc) {
    whiten(data, &ctx->keys[enc * 4]);

    uint32_t A = data->w[0];
    uint32_t B = data->w[1];
    uint32_t C = data->w[2];
    uint32_t D = data->w[3];

    uint32_t *keys = &ctx->keys[8];
    if (enc == TF_DECRYPT) {
        keys += 2 * 14 + 3;
    }

    for (int i = 16; i > 0; i--) {
        uint32_t T0 = round_g(ctx, A);
        uint32_t T1 = round_g(ctx, (B << 8) | (B >> 24));

        T0 += T1;
        T1 += T0;

        if (enc == TF_ENCRYPT) {
            C ^= T0 + *keys++;
            C = (C >> 1) | (C << 31);
            D = (D << 1) | (D >> 31);
            D ^= T1 + *keys++;
        } else {
            D ^= T1 + *keys--;
            D = (D >> 1) | (D << 31);
            C = (C << 1) | (C >> 31);
            C ^= T0 + *keys--;
        }

        uint32_t temp = C;
        C = A;
        A = temp;
        temp = D;
        D = B;
        B = temp;
    }

    data->w[0] = C;
    data->w[1] = D;
    data->w[2] = A;
    data->w[3] = B;

    whiten(data, &ctx->keys[enc == TF_DECRYPT ? 0 : 4]);
}

void tf_init(tf_ctx *ctx) {
    // Initialize S-box and Q-box here (omitted for brevity)
    // You can fill in the necessary initialization code here
}

void tf_setkey(tf_ctx *ctx, void *key) {
    // Set key and initialize the Twofish context (omitted for brevity)
    // You can fill in the necessary key scheduling code here
}

void pad_data(char *data, size_t *len) {
    size_t padding = 16 - (*len % 16);
    for (size_t i = *len; i < *len + padding; i++) {
        data[i] = (char)padding; // PKCS#7 padding
    }
    *len += padding;
}

int main() {
    // Initialize Twofish context
    tf_ctx ctx;
    tf_init(&ctx);

    // Load the encryption key
    tf_key mk;

    // Read key from user input
    printf("Enter a 128-bit key (4 unsigned integers, space-separated):\n");
    for (int i = 0; i < 4; i++) {
        scanf("%u", &mk.q[i]); // Read 4 unsigned integers
    }
    tf_setkey(&ctx, &mk);
    
    // Open input file
    FILE *input_file = fopen("input.txt", "r");
    if (input_file == NULL) {
        perror("Error opening input file");
        return EXIT_FAILURE;
    }

    // Open output file
    FILE *output_file = fopen("output.txt", "wb");
    if (output_file == NULL) {
        perror("Error opening output file");
        fclose(input_file);
        return EXIT_FAILURE;
    }

    // Buffer for reading text data
    char text_buffer[64]; // Adjust size as needed
    tf_blk block;

    // Read data from input file, encrypt it, and write it to output file
    while (fgets(text_buffer, sizeof(text_buffer), input_file)) {
        // Get the length of the text and pad it
        size_t len = strlen(text_buffer);
        pad_data(text_buffer, &len); // Pad data to multiple of 16 bytes

        // Process the data in 16-byte blocks
        for (size_t i = 0; i < len; i += 16) {
            memset(&block, 0, sizeof(block)); // Clear the block before use
            memcpy(block.b, &text_buffer[i], 16); // Copy 16 bytes into the block

            // Encrypt the block
            tf_enc(&ctx, &block, TF_ENCRYPT);
            
            // Write the encrypted block to the output file
            fwrite(&block, sizeof(tf_blk), 1, output_file);
        }
    }

    // Clean up
    fclose(input_file);
    fclose(output_file);
    printf("File encryption completed.\n");

    return EXIT_SUCCESS;
}
