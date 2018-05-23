//
// Created by yinaoxiong on 2018/5/23.
//

#include "AES.h"

void AES::keyExpansion(word *w) {
    word temp;
    int i = 0;
    while (i < Nk) {
        w[i] = byteToWord(key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]);
        ++i;
    }
    i = Nk;
    while (i < 4 * (Nr + 1)) {
        temp = w[i - 1];
        if (i % Nk == 0) {
            word temp1 = rotWord(temp);
            w[i] = w[i - Nk] ^ subWord(temp1) ^ Rcon[i / Nk - 1];
        } else
            w[i] = w[i - Nk] ^ temp;
        ++i;
    }
}

word AES::byteToWord(byte &b1, byte &b2, byte &b3, byte &b4) {
    word result(0x00000000);
    word temp;
    temp = b1.to_ulong();
    temp <<= 24;
    result |= temp;
    temp = b2.to_ulong();
    temp <<= 16;
    result |= temp;
    temp = b3.to_ulong();
    temp <<= 8;
    result |= temp;
    temp = b4.to_ulong();
    result |= temp;
    return result;
}

word AES::rotWord(word &rw) {
    word high = rw << 8;
    word low = rw >> 24;
    return high | low;
}

word AES::subWord(word &sw) {
    word temp;
    for (int i = 0; i < 32; i += 8) {
        int row = sw[i + 7] * 8 + sw[i + 6] * 4 + sw[i + 5] * 2 + sw[i + 4];
        int col = sw[i + 3] * 8 + sw[i + 2] * 4 + sw[i + 1] * 2 + sw[i];
        byte val = beginSBox[row][col];
        for (int j = 0; j < 8; ++j) {
            temp[i + j] = val[i];
        }
    }
    return temp;
}


byte *AES::getKet() {
    return key;
}

void AES::setKey() {
    short int temp;
    for (auto &i : key) {
        cin >> hex >> temp;
        i = temp;
    }
}

void AES::subBytes(byte *mtx) {
    for (int i = 0; i < 16; ++i) {
        int row = mtx[i][7] * 8 + mtx[i][6] * 4 + mtx[i][5] * 2 + mtx[i][4];
        int col = mtx[i][3] * 8 + mtx[i][2] * 4 + mtx[i][1] * 2 + mtx[i][0];
        mtx[i] = beginSBox[row][col];
    }
}

void AES::shiftRows(byte *mtx) {
    // 第二行循环左移一位
    byte temp = mtx[4];
    for (int i = 0; i < 3; ++i)
        mtx[i + 4] = mtx[i + 5];
    mtx[7] = temp;
    // 第三行循环左移两位
    for (int i = 0; i < 2; ++i) {
        temp = mtx[i + 8];
        mtx[i + 8] = mtx[i + 10];
        mtx[i + 10] = temp;
    }
    // 第四行循环左移三位
    temp = mtx[15];
    for (int i = 3; i > 0; --i)
        mtx[i + 12] = mtx[i + 11];
    mtx[12] = temp;
}

byte AES::GFMul(byte a, byte b) {
    byte p = 0;
    byte hi_bit_set;
    for (int counter = 0; counter < 8; counter++) {
        if ((b & byte(1)) != 0) {
            p ^= a;
        }
        hi_bit_set = (byte) (a & byte(0x80));
        a <<= 1;
        if (hi_bit_set != 0) {
            a ^= 0x1b; /* x^8 + x^4 + x^3 + x + 1 */
        }
        b >>= 1;
    }
    return p;
}

void AES::mixColumns(byte *mtx) {
    byte arr[4];
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j)
            arr[j] = mtx[i + j * 4];

        mtx[i] = GFMul(0x02, arr[0]) ^ GFMul(0x03, arr[1]) ^ arr[2] ^ arr[3];
        mtx[i + 4] = arr[0] ^ GFMul(0x02, arr[1]) ^ GFMul(0x03, arr[2]) ^ arr[3];
        mtx[i + 8] = arr[0] ^ arr[1] ^ GFMul(0x02, arr[2]) ^ GFMul(0x03, arr[3]);
        mtx[i + 12] = GFMul(0x03, arr[0]) ^ arr[1] ^ arr[2] ^ GFMul(0x02, arr[3]);
    }
}

void AES::addRoundKey(byte *mtx, word *k) {
    for (int i = 0; i < 4; ++i) {
        word k1 = k[i] >> 24;
        word k2 = (k[i] << 8) >> 24;
        word k3 = (k[i] << 16) >> 24;
        word k4 = (k[i] << 24) >> 24;

        mtx[i] = mtx[i] ^ byte(k1.to_ulong());
        mtx[i + 4] = mtx[i + 4] ^ byte(k2.to_ulong());
        mtx[i + 8] = mtx[i + 8] ^ byte(k3.to_ulong());
        mtx[i + 12] = mtx[i + 12] ^ byte(k4.to_ulong());
    }
}

void AES::invSubBytes(byte *mtx) {
    for (int i = 0; i < 16; ++i) {
        int row = mtx[i][7] * 8 + mtx[i][6] * 4 + mtx[i][5] * 2 + mtx[i][4];
        int col = mtx[i][3] * 8 + mtx[i][2] * 4 + mtx[i][1] * 2 + mtx[i][0];
        mtx[i] = endSBox[row][col];
    }
}

void AES::invShiftRows(byte *mtx) {
    // 第二行循环右移一位
    byte temp = mtx[7];
    for (int i = 3; i > 0; --i)
        mtx[i + 4] = mtx[i + 3];
    mtx[4] = temp;
    // 第三行循环右移两位
    for (int i = 0; i < 2; ++i) {
        temp = mtx[i + 8];
        mtx[i + 8] = mtx[i + 10];
        mtx[i + 10] = temp;
    }
    // 第四行循环右移三位
    temp = mtx[12];
    for (int i = 0; i < 3; ++i)
        mtx[i + 12] = mtx[i + 13];
    mtx[15] = temp;
}

void AES::invMixColumns(byte *mtx) {
    byte arr[4];
    for(int i=0; i<4; ++i)
    {
        for(int j=0; j<4; ++j)
            arr[j] = mtx[i+j*4];

        mtx[i] = GFMul(0x0e, arr[0]) ^ GFMul(0x0b, arr[1]) ^ GFMul(0x0d, arr[2]) ^ GFMul(0x09, arr[3]);
        mtx[i+4] = GFMul(0x09, arr[0]) ^ GFMul(0x0e, arr[1]) ^ GFMul(0x0b, arr[2]) ^ GFMul(0x0d, arr[3]);
        mtx[i+8] = GFMul(0x0d, arr[0]) ^ GFMul(0x09, arr[1]) ^ GFMul(0x0e, arr[2]) ^ GFMul(0x0b, arr[3]);
        mtx[i+12] = GFMul(0x0b, arr[0]) ^ GFMul(0x0d, arr[1]) ^ GFMul(0x09, arr[2]) ^ GFMul(0x0e, arr[3]);
    }
}

void AES::encrypt(byte *in) {
    word theKey[4];
    for (int i = 0; i < 4; ++i) {
        theKey[i]=extenKey[i];
    }
    addRoundKey(in,theKey);
    for (int i = 1; i < Nr; ++i) {
        subBytes(in);
        shiftRows(in);
        mixColumns(in);
        for (int j = 0; j < 4; ++j) {
            theKey[j]=extenKey[4*i+j];
        }
        addRoundKey(in,theKey);
    }
    subBytes(in);
    shiftRows(in);
    for (int i = 0; i < 4; ++i) {
        theKey[i]=extenKey[4*Nr+i];
    }
    addRoundKey(in,theKey);
}

void AES::decrypt(byte *in) {
    word theKey[4];
    for (int i = 0; i < 4; ++i) {
        theKey[i]=extenKey[4*Nr+i];
    }
    addRoundKey(in,theKey);
    for(int round=Nr-1;round>0;--round){
        invShiftRows(in);
        invSubBytes(in);
        for(int i=0;i<4;++i){
            theKey[i]=extenKey[4*round+i];
        }
        addRoundKey(in,theKey);
        invMixColumns(in);
    }
    invShiftRows(in);
    invSubBytes(in);
    for(int i=0;i<4;++i){
        theKey[i]=extenKey[i];
    }
    addRoundKey(in,theKey);
}

AES::AES() {
    //初始化拓展密钥
    auto * longKey=new word[4*(Nr+1)];
    keyExpansion(longKey);
    extenKey=longKey;
}


