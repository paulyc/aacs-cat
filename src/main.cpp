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
#include <gcrypt.h>

static void printhex(uint8_t *data, int len)
{
    for (int i = 0; i < len; ++i) {
        printf("%02X", data[i]);
    }
}

#define IN
#define OUT

int find_vuk(IN const char *mkb_filename, IN uint8_t *vid, IN struct pk_entry *pkl, IN size_t pkl_len, OUT uint8_t *mk, OUT uint8_t *vuk)
{
    int ret = -1;
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

    for (size_t pki = 0; pki < pkl_len && ret != 0; ++pki) {
        const uint8_t *pk = pkl[pki].key;
        for (unsigned uvi = 0; uvi < num_uvs && ret != 0; uvi++) {
            const uint8_t *cvalue = cvalues + uvi * 16;
            const uint8_t *uv     = uvs + 1 + uvi * 5;
            gcry_cipher_hd_t gcry_h;
            uint8_t dec_vd[16];

            gcry_cipher_open(&gcry_h, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_ECB, 0);
            gcry_cipher_setkey(gcry_h, pk, 16);
            gcry_cipher_decrypt(gcry_h, mk, 16, cvalue, 16);

            for (int a = 0; a < 4; a++) {
                mk[a + 12] ^= uv[a];
            }

            gcry_cipher_setkey(gcry_h, mk, 16);
            gcry_cipher_decrypt (gcry_h, dec_vd, 16, vd, 16);
            gcry_cipher_close(gcry_h);

            if (!memcmp(dec_vd, "\x01\x23\x45\x67\x89\xAB\xCD\xEF", 8)) {
                printf("valid. mk is : ");
                printhex(mk, 16);
                printf("\n");
                crypto_aes128d(mk, vid, vuk);
                ret = 0;
            } else {
                //printf("invalid %d %d\n", uvi, num_uvs);
            }
        }
    }

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
    uint8_t encrypted[6128];
} __attribute__((packed));

int decrypt_m2ts(IN const char *encrypted_filename, IN const char *decrypted_filename, IN uint8_t *unit_key)
{
    int ret = 0;

    FILE *encrypted_m2ts = fopen(encrypted_filename, "rb");
    FILE *decrypted_m2ts = fopen(decrypted_filename, "wb");
    if (encrypted_m2ts == NULL) {
        fprintf(stderr, "error opening encrypted m2ts %s\n", encrypted_filename);
        return -1;
    }
    if (decrypted_m2ts == NULL) {
        fprintf(stderr, "error opening decrypted m2ts %s\n", decrypted_filename);
        fclose(encrypted_m2ts);
        return -1;
    }

    struct aacs_aligned_unit unit;
    while (!feof(encrypted_m2ts)) {
        size_t rd = fread(&unit, sizeof(struct aacs_aligned_unit), 1, encrypted_m2ts);
        if (rd == 0 && ferror(encrypted_m2ts)) {
            fprintf(stderr, "error reading %s\n", encrypted_filename);
            ret = ferror(encrypted_m2ts);
            break;
        }

        // calculate block key from seed and unit key
        uint8_t block_key[16];
        gcry_cipher_hd_t gcry_h;
        gcry_cipher_open(&gcry_h, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_ECB, 0);
        gcry_cipher_setkey(gcry_h, unit_key, 16);
        gcry_cipher_decrypt(gcry_h, block_key, 16, unit.seed, 16);
        gcry_cipher_close(gcry_h);

        for (int i = 0; i < 16; ++i) {
        }
    }

    fclose(encrypted_m2ts);
    fclose(decrypted_m2ts);
    return 0;
}

int main(int argc, char **argv)
{
    struct pk_entry pkl[1] = {{{0xAD,0x5E,0x54,0x6C,0x46,0xD7,0x2D,0xC0,0x83,0xAE,0xB5,0x68,0x69,0x24,0xE1,0xB3},NULL}};
    uint8_t vid[16] = {0xD7,0x18,0xB7,0x15,0xB7,0xF3,0x12,0x0B,0xF4,0x46,0x45,0x0D,0xB4,0x2C,0x34,0x2F};
    uint8_t mk[16];
    uint8_t vuk[16];

    if (find_vuk("./MKB_RO.inf", vid, pkl, sizeof(pkl), mk, vuk) != 0) {
        fprintf(stderr, "could not find vuk\n");
        return -1;
    }

    printf("vuk is : ");
    printhex(vuk, 16);
    printf("\n");

    const char *encrypted_unit_keys[] = {
        "\x0f\x19\xc2\xfd\x1e\xb4\x56\xbd\x6d\x0c\x74\xae\xa8\xe7\xc2\x36",
        "\xf3\x63\x25\xe2\x7a\xa5\xdc\xdf\xba\x15\x16\x83\x25\x74\x37\xe3",
        "\x53\x12\xca\x39\x68\x7a\x3e\x72\x7b\xfa\x8c\x6b\x6b\x4d\x6e\xcd"
    };
    uint8_t decrypted_unit_keys[3][16];

    for (int i = 0; i < 3; ++i) {
        decrypt_unit_key(vuk, (const uint8_t*)encrypted_unit_keys[i], decrypted_unit_keys[i]);

        printf("decrypted unit key %d : ", i);
        printhex(decrypted_unit_keys[i], 16);
        printf("\n");
    }

    return 0;
}
