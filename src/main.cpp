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

#include <stdio.h>
#include <gcrypt.h>

void printhex(uint8_t *data, int len)
{
    for (int i = 0; i < len; ++i) {
        printf("%02X", data[i]);
    }
}

int main(int argc, char **argv)
{
    FILE *mkbfile = fopen("./MKB_RO.inf", "rb");
    fseek(mkbfile, 0, SEEK_END);
    long flen = ftell(mkbfile);
    fseek(mkbfile, 0, SEEK_SET);
    uint8_t *data = (uint8_t*)malloc(flen);
    fread(data, 1, flen, mkbfile);
    MKB *mkb = mkb_init(data, flen);

    size_t len;
    uint8_t mk[16];
    uint8_t vuk[16];
    uint8_t vid[16] = {0xD7,0x18,0xB7,0x15,0xB7,0xF3,0x12,0x0B,0xF4,0x46,0x45,0x0D,0xB4,0x2C,0x34,0x2F};
    const uint8_t *uvs     = mkb_subdiff_records(mkb, &len);
    const uint8_t *cvalues = mkb_cvalues(mkb, &len);
    const uint8_t *vd      = mkb_mk_dv(mkb);
    unsigned num_uvs = len / 5;

    struct pk_entry pkl[1] = {{{0xAD,0x5E,0x54,0x6C,0x46,0xD7,0x2D,0xC0,0x83,0xAE,0xB5,0x68,0x69,0x24,0xE1,0xB3},NULL}};
    const uint8_t *pk = pkl[0].key;
    for (unsigned uvi = 0; uvi < num_uvs; uvi++) {
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
            printf("vuk is : ");
            printhex(vuk, 16);
            printf("\n");
            break;
        } else {
            printf("invalid %d %d\n", uvi, num_uvs);
        }
    }

    mkb_close(mkb);
    fclose(mkbfile);
    return 0;
}
