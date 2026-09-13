#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* ---- Layer 1: decoy ------------------------------------------------- */
static const char *DECOY_PASSWORD = "letmein123";

/* ---- Layer 2: XOR-encoded target ------------------------------------ */
#define REAL_LEN 12

static const uint8_t XOR_KEY[REAL_LEN] = {
    0x5A, 0x13, 0x8C, 0x41, 0x27, 0x99,
    0x3E, 0x64, 0x0B, 0xD2, 0x77, 0x5F
};

/* TARGET_CIPHER[i] = XOR_KEY[i] ^ plaintext[i], computed offline.
 * Recovering the plaintext is: plaintext[i] = XOR_KEY[i] ^ TARGET_CIPHER[i] */
static const uint8_t TARGET_CIPHER[REAL_LEN] = {
    0x08, 0x76, 0xFA, 0x04, 0x49, 0xFE,
    0x61, 0x27, 0x79, 0xB9, 0x56, 0x7E
};

/* ---- Layer 3: checksum ------------------------------------------------
 * 16-bit rotate-left-1 then add, over the raw input bytes.
 */
#define EXPECTED_CHECKSUM 0xBB74

static uint16_t rolling_checksum(const char *s, size_t len) {
    uint16_t sum = 0;
    for (size_t i = 0; i < len; i++) {
        sum = (uint16_t)((sum << 1) | (sum >> 15)); /* rotate left 1, 16-bit */
        sum = (uint16_t)(sum + (uint8_t)s[i]);
    }
    return sum;
}

static int check_layer2(const char *input) {
    if (strlen(input) != REAL_LEN) return 0;
    for (int i = 0; i < REAL_LEN; i++) {
        uint8_t input_ciphered = (uint8_t)input[i] ^ XOR_KEY[i];
        if (input_ciphered != TARGET_CIPHER[i]) return 0;
    }
    return 1;
}

static int check_layer3(const char *input) {
    return rolling_checksum(input, strlen(input)) == EXPECTED_CHECKSUM;
}

int main(void) {
    char input[128];

    printf("=== crackme01 ===\n");
    printf("Enter the password: ");
    fflush(stdout);

    if (!fgets(input, sizeof(input), stdin)) {
        fprintf(stderr, "Input error.\n");
        return 1;
    }
    size_t len = strlen(input);
    if (len && input[len - 1] == '\n') input[len - 1] = '\0';

    if (strcmp(input, DECOY_PASSWORD) == 0) {
        printf("Close, but no. Try harder.\n");
        return 1;
    }

    if (!check_layer2(input)) {
        printf("Access denied.\n");
        return 1;
    }

    if (!check_layer3(input)) {
        printf("Access denied.\n");
        return 1;
    }

    printf("Access granted. Correct password confirmed.\n");
    return 0;
}
