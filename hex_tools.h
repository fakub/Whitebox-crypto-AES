//
// Created by fakub on 19.10.15.
//

#ifndef WHITEBOX_CRYPTO_AES_HEX_TOOLS_H
#define WHITEBOX_CRYPTO_AES_HEX_TOOLS_H

#include "WBAES.h"

inline BYTE hex2val(const BYTE c) {
    if (c >= '0' && c <= '9') return (BYTE)(c - '0');
    if (c >= 'a' && c <= 'f') return (BYTE)(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return (BYTE)(c - 'A' + 10);
    throw runtime_error("invalid hex code.");
}

inline void hex2nbytes(const char * hexcode, BYTE * bytes, const BYTE n = 16) {
    for (BYTE i=0; i<n; i++)
        bytes[i] = 16 * hex2val(hexcode[2 * i]) + hex2val(hexcode[2 * i + 1]);
}

#endif //WHITEBOX_CRYPTO_AES_HEX_TOOLS_H
