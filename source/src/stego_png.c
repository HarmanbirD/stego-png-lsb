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
    if (!filename || !out)
    {
        SET_ERROR(err, "load_image: invalid arguments");
        return -1;
    }

    memset(out, 0, sizeof(*out));

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

    png_set_strip_16(png_ptr);
    png_set_expand(png_ptr);
    png_set_packing(png_ptr);

    png_read_update_info(png_ptr, info_ptr);

    out->width      = png_get_image_width(png_ptr, info_ptr);
    out->height     = png_get_image_height(png_ptr, info_ptr);
    out->color_type = png_get_color_type(png_ptr, info_ptr);
    out->bit_depth  = png_get_bit_depth(png_ptr, info_ptr);

    if (out->bit_depth != 8 ||
        (out->color_type != PNG_COLOR_TYPE_RGB && out->color_type != PNG_COLOR_TYPE_RGBA))
    {
        SET_ERROR(err, "Unsupported PNG format after normalization (need RGB/RGBA 8-bit)");
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        fclose(fp);
        return -1;
    }

    // Allocate rows
    png_size_t rowbytes = png_get_rowbytes(png_ptr, info_ptr);

    out->rows = (png_bytep *)calloc(out->height, sizeof(png_bytep));
    if (!out->rows)
    {
        SET_ERROR(err, "Out of memory allocating row pointers");
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        fclose(fp);
        return -1;
    }

    for (png_uint_32 y = 0; y < out->height; y++)
    {
        out->rows[y] = (png_bytep)malloc(rowbytes);
        if (!out->rows[y])
        {
            SET_ERROR(err, "Out of memory allocating PNG row");
            for (png_uint_32 i = 0; i < y; i++)
                free(out->rows[i]);
            free(out->rows);
            out->rows = NULL;

            png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
            fclose(fp);
            return -1;
        }
    }

    png_read_image(png_ptr, out->rows);

    png_read_end(png_ptr, NULL);

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

static inline uint8_t get_lsb(uint8_t byte)
{
    return (uint8_t)(byte & 0x01u);
}

static inline uint32_t read_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           ((uint32_t)p[3] << 0);
}

int extract_data(stego_image *img, uint8_t **out_payload, size_t *out_len, struct fsm_error *err)
{
    if (!img || !img->rows || !out_payload || !out_len)
    {
        SET_ERROR(err, "extract_data: invalid arguments");
        return -1;
    }

    *out_payload = NULL;
    *out_len     = 0;

    if (img->bit_depth != 8)
    {
        SET_ERROR(err, "extract_data: image must be normalized to 8-bit channels");
        return -1;
    }

    if (img->color_type != PNG_COLOR_TYPE_RGB && img->color_type != PNG_COLOR_TYPE_RGBA)
    {
        SET_ERROR(err, "extract_data: only RGB/RGBA PNG images are supported");
        return -1;
    }

    const int    bytes_per_pixel = (img->color_type == PNG_COLOR_TYPE_RGBA) ? 4 : 3;
    const int    usable_channels = 3;
    const size_t capacity_bits =
        (size_t)img->width * (size_t)img->height * (size_t)usable_channels;

    if (capacity_bits < (size_t)STEG_HEADER_LEN * 8u)
    {
        SET_ERROR(err, "extract_data: image too small to contain a valid header");
        return -1;
    }

    uint8_t header[STEG_HEADER_LEN];
    memset(header, 0, sizeof(header));

    size_t bit_index = 0;

    for (size_t i = 0; i < STEG_HEADER_LEN; i++)
    {
        uint8_t out_byte = 0;

        for (int b = 7; b >= 0; b--)
        {
            size_t pix_i = bit_index / (size_t)usable_channels;
            size_t chan  = bit_index % (size_t)usable_channels;

            png_uint_32 y = (png_uint_32)(pix_i / (size_t)img->width);
            png_uint_32 x = (png_uint_32)(pix_i % (size_t)img->width);

            png_bytep row = img->rows[y];
            png_bytep px  = row + (size_t)x * (size_t)bytes_per_pixel;

            uint8_t bit = get_lsb(px[(int)chan]);
            out_byte |= (uint8_t)(bit << b);

            bit_index++;
        }

        header[i] = out_byte;
    }

    if (memcmp(header, STEG_MAGIC, 4) != 0)
    {
        SET_ERROR(err, "extract_data: missing STEG magic (no hidden payload found)");
        return -1;
    }

    if (header[4] != (uint8_t)STEG_VER)
    {
        SET_ERROR(err, "extract_data: unsupported STEG version");
        return -1;
    }

    const uint8_t *len_ptr    = header + (4 + 1 + SALT_LEN + IV_LEN);
    uint32_t       ct_len_u32 = read_be32(len_ptr);

    if (ct_len_u32 == 0)
    {
        SET_ERROR(err, "extract_data: ciphertext length is zero");
        return -1;
    }

    size_t total_len = (size_t)STEG_HEADER_LEN + (size_t)ct_len_u32;

    if (total_len * 8u > capacity_bits)
    {
        SET_ERROR(err, "extract_data: declared payload length exceeds image capacity");
        return -1;
    }

    uint8_t *payload = (uint8_t *)malloc(total_len);
    if (!payload)
    {
        SET_ERROR(err, "extract_data: out of memory");
        return -1;
    }
    memcpy(payload, header, STEG_HEADER_LEN);

    for (size_t i = STEG_HEADER_LEN; i < total_len; i++)
    {
        uint8_t out_byte = 0;

        for (int b = 7; b >= 0; b--)
        {
            size_t pix_i = bit_index / (size_t)usable_channels;
            size_t chan  = bit_index % (size_t)usable_channels;

            png_uint_32 y = (png_uint_32)(pix_i / (size_t)img->width);
            png_uint_32 x = (png_uint_32)(pix_i % (size_t)img->width);

            png_bytep row = img->rows[y];
            png_bytep px  = row + (size_t)x * (size_t)bytes_per_pixel;

            uint8_t bit = get_lsb(px[(int)chan]);
            out_byte |= (uint8_t)(bit << b);

            bit_index++;
        }

        payload[i] = out_byte;
    }

    *out_payload = payload;
    *out_len     = total_len;
    return 0;
}

int decrypt_data(const uint8_t    *payload,
                 size_t            payload_len,
                 const char       *password,
                 uint8_t         **out_plain,
                 size_t           *out_plain_len,
                 struct fsm_error *err)
{
    if (!payload || !password || !out_plain || !out_plain_len)
    {
        SET_ERROR(err, "decrypt_data: invalid arguments");
        return -1;
    }

    *out_plain     = NULL;
    *out_plain_len = 0;

    if (payload_len < STEG_HEADER_LEN)
    {
        SET_ERROR(err, "decrypt_data: payload too small to contain header");
        return -1;
    }

    if (memcmp(payload, STEG_MAGIC, 4) != 0)
    {
        SET_ERROR(err, "decrypt_data: invalid magic (not a STEG payload)");
        return -1;
    }

    if (payload[4] != (uint8_t)STEG_VER)
    {
        SET_ERROR(err, "decrypt_data: unsupported STEG version");
        return -1;
    }

    const uint8_t *salt = payload + 4 + 1;
    const uint8_t *iv   = payload + 4 + 1 + SALT_LEN;

    const uint8_t *len_ptr    = payload + 4 + 1 + SALT_LEN + IV_LEN;
    uint32_t       ct_len_u32 = read_be32(len_ptr);

    if (ct_len_u32 == 0)
    {
        SET_ERROR(err, "decrypt_data: ciphertext length is zero");
        return -1;
    }

    size_t ct_len = (size_t)ct_len_u32;

    size_t expected_total = (size_t)STEG_HEADER_LEN + ct_len;
    if (payload_len < expected_total)
    {
        SET_ERROR(err, "decrypt_data: payload truncated (length mismatch)");
        return -1;
    }

    const uint8_t *ciphertext = payload + STEG_HEADER_LEN;

    uint8_t key[KEY_LEN];
    if (PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
                          salt, SALT_LEN,
                          PBKDF_ITERS,
                          EVP_sha256(),
                          KEY_LEN, key) != 1)
    {
        OPENSSL_cleanse(key, sizeof(key));
        SET_ERROR(err, "decrypt_data: PBKDF2 key derivation failed");
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        OPENSSL_cleanse(key, sizeof(key));
        SET_ERROR(err, "decrypt_data: EVP_CIPHER_CTX_new failed");
        return -1;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(key, sizeof(key));
        SET_ERROR(err, "decrypt_data: EVP_DecryptInit_ex failed");
        return -1;
    }

    uint8_t *plaintext = (uint8_t *)malloc(ct_len);
    if (!plaintext)
    {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(key, sizeof(key));
        SET_ERROR(err, "decrypt_data: out of memory");
        return -1;
    }

    int outl1 = 0, outl2 = 0;
    if (EVP_DecryptUpdate(ctx, plaintext, &outl1, ciphertext, (int)ct_len) != 1)
    {
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(key, sizeof(key));
        SET_ERROR(err, "decrypt_data: EVP_DecryptUpdate failed");
        return -1;
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext + outl1, &outl2) != 1)
    {
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(key, sizeof(key));
        SET_ERROR(err, "decrypt_data: decryption failed (wrong key or corrupted data)");
        return -1;
    }

    size_t pt_len = (size_t)(outl1 + outl2);

    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(key, sizeof(key));

    *out_plain     = plaintext;
    *out_plain_len = pt_len;
    return 0;
}

int write_bytes_to_file(const char *path, const uint8_t *buf, size_t len, struct fsm_error *err)
{
    if (!path || !buf || len == 0)
    {
        SET_ERROR(err, "write_bytes_to_file: invalid arguments");
        return -1;
    }

    FILE *fp = fopen(path, "wb");
    if (!fp)
    {
        SET_ERROR(err, "write_bytes_to_file: could not open output file");
        return -1;
    }

    size_t n = fwrite(buf, 1, len, fp);
    if (fclose(fp) != 0)
    {
        SET_ERROR(err, "write_bytes_to_file: fclose failed");
        return -1;
    }

    if (n != len)
    {
        SET_ERROR(err, "write_bytes_to_file: short write");
        return -1;
    }

    return 0;
}

static void copy_png_metadata(png_structp rpng, png_infop rinfo,
                              png_structp wpng, png_infop winfo)
{
    png_textp text_ptr = NULL;
    int       num_text = 0;
    if (png_get_text(rpng, rinfo, &text_ptr, &num_text) > 0 && text_ptr && num_text > 0)
    {
        png_set_text(wpng, winfo, text_ptr, num_text);
    }

    png_uint_32 res_x, res_y;
    int         unit_type;
    if (png_get_pHYs(rpng, rinfo, &res_x, &res_y, &unit_type) == PNG_INFO_pHYs)
    {
        png_set_pHYs(wpng, winfo, res_x, res_y, unit_type);
    }

    double gamma;
    if (png_get_gAMA(rpng, rinfo, &gamma) == PNG_INFO_gAMA)
    {
        png_set_gAMA(wpng, winfo, gamma);
    }

    int intent;
    if (png_get_sRGB(rpng, rinfo, &intent) == PNG_INFO_sRGB)
    {
        png_set_sRGB(wpng, winfo, intent);
    }

    png_charp   name             = NULL;
    png_bytep   profile          = NULL;
    png_uint_32 proflen          = 0;
    int         compression_type = 0;
    if (png_get_iCCP(rpng, rinfo, &name, &compression_type, &profile, &proflen) == PNG_INFO_iCCP)
    {
        png_set_iCCP(wpng, winfo, name, compression_type, profile, proflen);
    }

    png_timep mod_time = NULL;
    if (png_get_tIME(rpng, rinfo, &mod_time) == PNG_INFO_tIME && mod_time)
    {
        png_set_tIME(wpng, winfo, mod_time);
    }
}

int write_stego_png(const char *out_path, stego_image *img, struct fsm_error *err)
{
    if (!out_path || !img || !img->rows)
    {
        SET_ERROR(err, "write_stego_png: invalid arguments");
        return -1;
    }

    FILE *fp = fopen(out_path, "wb");
    if (!fp)
    {
        SET_ERROR(err, "write_stego_png: could not open output PNG");
        return -1;
    }

    png_structp png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png_ptr)
    {
        fclose(fp);
        SET_ERROR(err, "write_stego_png: png_create_write_struct failed");
        return -1;
    }

    png_infop info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr)
    {
        png_destroy_write_struct(&png_ptr, NULL);
        fclose(fp);
        SET_ERROR(err, "write_stego_png: png_create_info_struct failed");
        return -1;
    }

    if (setjmp(png_jmpbuf(png_ptr)))
    {
        png_destroy_write_struct(&png_ptr, &info_ptr);
        fclose(fp);
        SET_ERROR(err, "write_stego_png: libpng write error");
        return -1;
    }

    png_init_io(png_ptr, fp);

    png_set_IHDR(png_ptr,
                 info_ptr,
                 img->width,
                 img->height,
                 img->bit_depth,
                 img->color_type,
                 PNG_INTERLACE_NONE,
                 PNG_COMPRESSION_TYPE_BASE,
                 PNG_FILTER_TYPE_BASE);

    if (img->png_ptr && img->info_ptr)
    {
        copy_png_metadata(img->png_ptr, img->info_ptr, png_ptr, info_ptr);
    }

    png_write_info(png_ptr, info_ptr);
    png_write_image(png_ptr, img->rows);
    png_write_end(png_ptr, info_ptr);

    png_destroy_write_struct(&png_ptr, &info_ptr);

    if (fclose(fp) != 0)
    {
        SET_ERROR(err, "write_stego_png: fclose failed");
        return -1;
    }

    return 0;
}

void free_image(stego_image *img)
{
    if (!img)
        return;

    if (img->rows)
    {
        for (png_uint_32 y = 0; y < img->height; y++)
        {
            free(img->rows[y]);
        }
        free(img->rows);
        img->rows = NULL;
    }

    if (img->png_ptr || img->info_ptr)
    {
        png_structp p = img->png_ptr;
        png_infop   i = img->info_ptr;
        png_destroy_read_struct(&p, &i, NULL);
        img->png_ptr  = NULL;
        img->info_ptr = NULL;
    }

    if (img->fp)
    {
        fclose(img->fp);
        img->fp = NULL;
    }

    img->width = img->height = 0;
    img->bit_depth           = 0;
    img->color_type          = 0;
}
