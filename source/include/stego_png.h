#ifndef STEGO_PNG_H
#define STEGO_PNG_H

#include "fsm.h"
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <png.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define PNG_SIG_BYTES 8
#define STEG_MAGIC "STEG"
#define STEG_VER 1
#define SALT_LEN 16
#define IV_LEN 16
#define KEY_LEN 32
#define PBKDF_ITERS 200000

int load_image(char *filename, stego_image *out, struct fsm_error *err);
int encrypt_data(const char *filename, const char *password, uint8_t **out_buf, size_t *out_len, struct fsm_error *err);
int extract_data(char *filename, char **buffer);
int embed_data(stego_image *img, const uint8_t *payload, size_t payload_len, struct fsm_error *err);

// static int encrypt_data_handler(struct fsm_context *context, struct fsm_error *err);
// static int extract_data_handler(struct fsm_context *context, struct fsm_error *err);
// static int embed_data_handler(struct fsm_context *context, struct fsm_error *err);
// static int output_handler(struct fsm_context *context, struct fsm_error *err);
// static int decrypt_data_handler(struct fsm_context *context, struct fsm_error *err);

#endif // STEGO_PNG_H
