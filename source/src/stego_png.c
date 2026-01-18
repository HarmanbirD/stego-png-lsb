#include "stego_png.h"

static int is_png(FILE *fp, struct fsm_error *err)
{
    png_byte header[PNG_SIG_BYTES];

    if (fread(header, 1, PNG_SIG_BYTES, fp) != PNG_SIG_BYTES)
    {
        SET_ERROR(err, "PNG file is smaller than 8 bytes");
        return -1;
    }

    if (png_sig_cmp(header, 0, PNG_SIG_BYTES) != 0)
    {
        SET_ERROR(err, "PNG file is not a PNG.");
        return -1;
    }

    return 0;
}

int load_image(char *filename, stego_image *out, struct fsm_error *err)
{
    FILE *fp = fopen(filename, "rb");
    if (!fp)
    {
        SET_ERROR(err, "File could not be opened");
        return -1;
    }

    if (is_png(fp, err) != 0)
    {
        fclose(fp);
        return -1;
    }

    png_structp png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png_ptr)
    {
        SET_ERROR(err, "png_create_read_struct failed");
        fclose(fp);
        return -1;
    }

    png_infop info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr)
    {
        SET_ERROR(err, "png_create_info_struct failed");
        png_destroy_read_struct(&png_ptr, NULL, NULL);
        fclose(fp);
        return -1;
    }

    if (setjmp(png_jmpbuf(png_ptr)))
    {
        SET_ERROR(err, "libpng error while reading PNG");
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        fclose(fp);
        return -1;
    }

    png_init_io(png_ptr, fp);

    png_set_sig_bytes(png_ptr, PNG_SIG_BYTES);

    png_read_info(png_ptr, info_ptr);

    out->width      = png_get_image_width(png_ptr, info_ptr);
    out->height     = png_get_image_height(png_ptr, info_ptr);
    out->color_type = png_get_color_type(png_ptr, info_ptr);
    out->bit_depth  = png_get_bit_depth(png_ptr, info_ptr);

    out->png_ptr  = png_ptr;
    out->info_ptr = info_ptr;
    out->fp       = fp;

    return 0;
}

static int read_entire_file(const char *filename, uint8_t **out, size_t *out_len, struct fsm_error *err)
{
    FILE *fp = fopen(filename, "rb");
    if (!fp)
    {
        SET_ERROR(err, "Could not open input file");
        return -1;
    }

    if (fseek(fp, 0, SEEK_END) != 0)
    {
        fclose(fp);
        SET_ERROR(err, "fseek failed");
        return -1;
    }

    long sz = ftell(fp);
    if (sz < 0)
    {
        fclose(fp);
        SET_ERROR(err, "ftell failed");
        return -1;
    }
    if (sz == 0)
    {
        fclose(fp);
        SET_ERROR(err, "Input file is empty");
        return -1;
    }
    rewind(fp);

    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (!buf)
    {
        fclose(fp);
        SET_ERROR(err, "Out of memory");
        return -1;
    }

    size_t n = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);

    if (n != (size_t)sz)
    {
        free(buf);
        SET_ERROR(err, "Failed to read full input file");
        return -1;
    }

    *out     = buf;
    *out_len = (size_t)sz;
    return 0;
}

int encrypt_data(const char *filename, const char *password, uint8_t **out_buf, size_t *out_len, struct fsm_error *err)
{
    if (!filename || !password || !out_buf || !out_len)
    {
        SET_ERROR(err, "encrypt_data: invalid arguments");
        return -1;
    }

    *out_buf = NULL;
    *out_len = 0;

    uint8_t *plaintext = NULL;
    size_t   pt_len    = 0;
    if (read_entire_file(filename, &plaintext, &pt_len, err) != 0)
        return -1;

    uint8_t salt[SALT_LEN];
    uint8_t iv[IV_LEN];

    if (RAND_bytes(salt, SALT_LEN) != 1)
    {
        free(plaintext);
        SET_ERROR(err, "RAND_bytes failed (salt)");
        return -1;
    }

    if (RAND_bytes(iv, IV_LEN) != 1)
    {
        free(plaintext);
        SET_ERROR(err, "RAND_bytes failed (iv)");
        return -1;
    }

    uint8_t key[KEY_LEN];
    if (PKCS5_PBKDF2_HMAC(password, (int)strlen(password), salt, SALT_LEN,
                          PBKDF_ITERS, EVP_sha256(), KEY_LEN, key) != 1)
    {
        free(plaintext);
        SET_ERROR(err, "PBKDF2 key derivation failed");
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        free(plaintext);
        SET_ERROR(err, "EVP_CIPHER_CTX_new failed");
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        SET_ERROR(err, "EVP_EncryptInit_ex failed");
        return -1;
    }

    int    block_size = EVP_CIPHER_block_size(EVP_aes_256_cbc());
    size_t ct_cap     = pt_len + (size_t)block_size;

    uint8_t *ciphertext = (uint8_t *)malloc(ct_cap);
    if (!ciphertext)
    {
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        SET_ERROR(err, "Out of memory (ciphertext)");
        return -1;
    }

    int outl1 = 0, outl2 = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext, &outl1, plaintext, (int)pt_len) != 1)
    {
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        SET_ERROR(err, "EVP_EncryptUpdate failed");
        return -1;
    }
    if (EVP_EncryptFinal_ex(ctx, ciphertext + outl1, &outl2) != 1)
    {
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        SET_ERROR(err, "EVP_EncryptFinal_ex failed");
        return -1;
    }

    size_t ct_len = (size_t)(outl1 + outl2);
    EVP_CIPHER_CTX_free(ctx);

    size_t header_len = 4 + 1 + SALT_LEN + IV_LEN + 4;
    size_t total_len  = header_len + ct_len;

    uint8_t *blob = (uint8_t *)malloc(total_len);
    if (!blob)
    {
        free(ciphertext);
        free(plaintext);
        SET_ERROR(err, "Out of memory (output blob)");
        return -1;
    }

    uint8_t *p = blob;
    memcpy(p, STEG_MAGIC, 4);
    p += 4;
    *p++ = (uint8_t)STEG_VER;

    memcpy(p, salt, SALT_LEN);
    p += SALT_LEN;
    memcpy(p, iv, IV_LEN);
    p += IV_LEN;

    uint32_t be_len = htonl((uint32_t)ct_len);
    memcpy(p, &be_len, 4);
    p += 4;

    memcpy(p, ciphertext, ct_len);

    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(plaintext, pt_len);

    free(ciphertext);
    free(plaintext);

    *out_buf = blob;
    *out_len = total_len;
    return 0;
}

static inline uint8_t set_lsb(uint8_t byte, uint8_t bit)
{
    return (uint8_t)((byte & 0xFEu) | (bit & 0x01u));
}

int embed_data(stego_image *img, const uint8_t *payload, size_t payload_len, struct fsm_error *err)
{
    if (!img || !img->rows || !payload || payload_len == 0)
    {
        SET_ERROR(err, "embed_data: invalid arguments");
        return -1;
    }

    if (img->bit_depth != 8)
    {
        SET_ERROR(err, "embed_data: image must be normalized to 8-bit channels");
        return -1;
    }

    if (img->color_type != PNG_COLOR_TYPE_RGB && img->color_type != PNG_COLOR_TYPE_RGBA)
    {
        SET_ERROR(err, "embed_data: only RGB/RGBA PNG images are supported");
        return -1;
    }

    const int bytes_per_pixel = (img->color_type == PNG_COLOR_TYPE_RGBA) ? 4 : 3;
    const int usable_channels = 3;

    const size_t capacity_bits = (size_t)img->width * (size_t)img->height * (size_t)usable_channels;

    const size_t needed_bits = payload_len * 8u;

    if (needed_bits > capacity_bits)
    {
        SET_ERROR(err, "embed_data: payload too large for this image capacity");
        return -1;
    }

    size_t bit_index = 0;

    for (png_uint_32 y = 0; y < img->height && bit_index < needed_bits; y++)
    {
        png_bytep row = img->rows[y];

        for (png_uint_32 x = 0; x < img->width && bit_index < needed_bits; x++)
        {
            png_bytep px = row + (size_t)x * (size_t)bytes_per_pixel;

            for (int c = 0; c < usable_channels && bit_index < needed_bits; c++)
            {
                const size_t  byte_i = bit_index / 8u;
                const int     bit_in = 7 - (int)(bit_index % 8u);
                const uint8_t bit    = (uint8_t)((payload[byte_i] >> bit_in) & 0x01u);

                px[c] = set_lsb(px[c], bit);
                bit_index++;
            }
        }
    }

    if (bit_index != needed_bits)
    {
        SET_ERROR(err, "embed_data: internal error (did not embed full payload)");
        return -1;
    }

    return 0;
}
