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

#define STEG_HEADER_LEN (4 + 1 + SALT_LEN + IV_LEN + 4)

int  load_image(char *filename, stego_image *out, struct fsm_error *err);
int  encrypt_data(const char *filename, const char *password, uint8_t **out_buf, size_t *out_len, struct fsm_error *err);
int  embed_data(stego_image *img, const uint8_t *payload, size_t payload_len, struct fsm_error *err);
int  extract_data(stego_image *img, uint8_t **out_payload, size_t *out_len, struct fsm_error *err);
int  decrypt_data(const uint8_t *payload, size_t payload_len, const char *password, uint8_t **out_plain, size_t *out_plain_len, struct fsm_error *err);
int  write_stego_png(const char *out_path, stego_image *img, struct fsm_error *err);
int  write_bytes_to_file(const char *path, const uint8_t *buf, size_t len, struct fsm_error *err);
void free_image(stego_image *img);

#endif // STEGO_PNG_H
