/**
    main.cpp

    aacs-cat - decrypt aacs mpeg2 transport stream given volume key or 
               volume id+media key block

    Copyright (C) 2019 Paul Ciarlo <paul.ciarlo@gmail.com>

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

extern "C"
{
#include "../contrib/libaacs/src/libaacs/mkb.h"
#include "../contrib/libaacs/src/libaacs/crypto.h"
#include "../contrib/libaacs/src/file/keydbcfg.h"
}

#include "../contrib/install/include/gcrypt.h"

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <gcrypt.h>

static void fprinthex(FILE *f, uint8_t *data, int len)
{
    for (int i = 0; i < len; ++i) {
        fprintf(f, "%02X", data[i]);
    }
}

#define IN
#define OUT

int find_vuk(IN const char *mkb_filename, IN uint8_t *vid, IN struct pk_entry *pkl, IN size_t pkl_len, OUT uint8_t *mk, OUT uint8_t *vuk)
{
    int ret = -1;
    gcry_cipher_hd_t gcry_h;
    uint8_t dec_vd[16];

    FILE *mkbfile = fopen(mkb_filename, "rb");
    if (mkbfile == NULL) {
        fprintf(stderr, "media key block file %s not found\n", mkb_filename);
        return ret;
    }

    fseek(mkbfile, 0, SEEK_END);
    long flen = ftell(mkbfile);
    fseek(mkbfile, 0, SEEK_SET);
    uint8_t *data = (uint8_t*)malloc(flen);
    fread(data, 1, flen, mkbfile);
    fclose(mkbfile);

    MKB *mkb = mkb_init(data, flen);

    size_t len;
    const uint8_t *uvs     = mkb_subdiff_records(mkb, &len);
    const uint8_t *cvalues = mkb_cvalues(mkb, &len);
    const uint8_t *vd      = mkb_mk_dv(mkb);
    unsigned num_uvs       = len / 5;

    gcry_cipher_open(&gcry_h, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_ECB, 0);

    for (size_t pki = 0; pki < pkl_len && ret != 0; ++pki) {
        const uint8_t *pk = pkl[pki].key;
        for (unsigned uvi = 0; uvi < num_uvs && ret != 0; uvi++) {
            const uint8_t *cvalue = cvalues + uvi * 16;
            const uint8_t *uv     = uvs + 1 + uvi * 5;

            gcry_cipher_setkey(gcry_h, pk, 16);
            gcry_cipher_decrypt(gcry_h, mk, 16, cvalue, 16);

            for (int a = 0; a < 4; a++) {
                mk[a + 12] ^= uv[a];
            }

            gcry_cipher_setkey(gcry_h, mk, 16);
            gcry_cipher_decrypt (gcry_h, dec_vd, 16, vd, 16);

            if (!memcmp(dec_vd, "\x01\x23\x45\x67\x89\xAB\xCD\xEF", 8)) {
                fprintf(stderr, "valid. mk is : ");
                fprinthex(stderr, mk, 16);
                fprintf(stderr, "\n");
                crypto_aes128d(mk, vid, vuk);
                ret = 0;
            } else {
                fprintf(stderr, "invalid %d %d\n", uvi, num_uvs);
            }
        }
    }

    gcry_cipher_close(gcry_h);
    mkb_close(mkb);

    return ret;
}

int decrypt_unit_key(IN uint8_t *vuk, IN const uint8_t *encrypted_unit_key, OUT uint8_t *decrypted_unit_key)
{
    gcry_cipher_hd_t gcry_h;
    gcry_cipher_open(&gcry_h, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_ECB, 0);
    gcry_cipher_setkey(gcry_h, vuk, 16);
    gcry_cipher_decrypt(gcry_h, decrypted_unit_key, 16, encrypted_unit_key, 16);
    gcry_cipher_close(gcry_h);
    return 0;
}

/* 6144 bytes, 3 logical sectors */
struct aacs_aligned_unit
{
    uint8_t seed[16];
    uint8_t ciphertext[6128];
} __attribute__((packed));

int decrypt_m2ts(IN const char *encrypted_filename, IN const uint8_t *const unit_key)
{
    int ret = 0;
    uint8_t block_key[16];
    gcry_cipher_hd_t gcry_h;
    struct aacs_aligned_unit unit;

    FILE *encrypted_m2ts = fopen(encrypted_filename, "rb");
    if (encrypted_m2ts == NULL) {
        fprintf(stderr, "error opening encrypted m2ts %s\n", encrypted_filename);
        return -1;
    }

    gcry_cipher_open(&gcry_h, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_ECB, 0);

    while (!feof(encrypted_m2ts)) {
        ssize_t wr;
        size_t rd = fread(&unit, sizeof(struct aacs_aligned_unit), 1, encrypted_m2ts);
        if (rd == 0 && ferror(encrypted_m2ts)) {
            fprintf(stderr, "error reading %s\n", encrypted_filename);
            ret = ferror(encrypted_m2ts);
            break;
        }

        // calculate block key from seed and unit key
        gcry_cipher_setkey(gcry_h, unit_key, 16);
        gcry_cipher_decrypt(gcry_h, block_key, 16, unit.seed, 16);

        for (int a = 0; a < 4; a++) {
            block_key[a + 12] ^= unit.seed[a];
        }

        // decrypt unit
        gcry_cipher_setkey(gcry_h, block_key, 16);
        gcry_cipher_decrypt(gcry_h, unit.ciphertext, sizeof(unit.ciphertext), NULL, 0);

        // write to output
        wr = write(STDOUT_FILENO, unit.ciphertext, sizeof(unit.ciphertext));
        if (wr == -1) {
            ret = errno;
            fprintf(stderr, "error writing: [%d] %s\n", ret, strerror(ret));
            break;
        }
    }

    gcry_cipher_close(gcry_h);
    fclose(encrypted_m2ts);

    return ret;
}

int main(int argc, char **argv)
{
    struct pk_entry pkl[1] = {{{0xAD,0x5E,0x54,0x6C,0x46,0xD7,0x2D,0xC0,0x83,0xAE,0xB5,0x68,0x69,0x24,0xE1,0xB3},NULL}};
    uint8_t vid[16] = {0xD7,0x18,0xB7,0x15,0xB7,0xF3,0x12,0x0B,0xF4,0x46,0x45,0x0D,0xB4,0x2C,0x34,0x2F};
    uint8_t mk[16];
    uint8_t vuk[16];

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <encrypted_m2ts>\n", argv[0]);
        return -1;
    }

    const int unit_key_indx = 0;

    int ret = find_vuk("./MKB_RO.inf", vid, pkl, sizeof(pkl), mk, vuk);
    if (ret != 0) {
        fprintf(stderr, "could not find vuk: error %d\n", ret);
        return ret;
    }

    fprintf(stderr, "vuk is : ");
    fprinthex(stderr, vuk, 16);
    fprintf(stderr, "\n");

    const char *encrypted_unit_keys[] = {
        "\x0f\x19\xc2\xfd\x1e\xb4\x56\xbd\x6d\x0c\x74\xae\xa8\xe7\xc2\x36",
        "\xf3\x63\x25\xe2\x7a\xa5\xdc\xdf\xba\x15\x16\x83\x25\x74\x37\xe3",
        "\x53\x12\xca\x39\x68\x7a\x3e\x72\x7b\xfa\x8c\x6b\x6b\x4d\x6e\xcd"
    };
    uint8_t decrypted_unit_keys[3][16];

    for (int i = 0; i < 3; ++i) {
        decrypt_unit_key(vuk, (const uint8_t*)encrypted_unit_keys[i], decrypted_unit_keys[i]);

        fprintf(stderr, "decrypted unit key %d : ", i);
        fprinthex(stderr, decrypted_unit_keys[i], 16);
        fprintf(stderr, "\n");
    }

    ret = decrypt_m2ts(argv[1], decrypted_unit_keys[unit_key_indx]);
    if (ret != 0) {
        fprintf(stderr, "decrypt_m2ts() failed: error %d\n", ret);
        return ret;
    }

    return 0;
}
