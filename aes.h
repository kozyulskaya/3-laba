//
// Created by Admin on 21.05.2021.
//

#ifndef IBZI_3_AES_H
#define IBZI_3_AES_H

#include "constants.h"

// Размер блока данных (в байтах)
#define BLOCK_SIZE 16
// Длина ключа (в байтах)
#define KEY_SIZE 16

class aes {
private:
    const byte *expanded_key;

    static void key_expansion_core(byte *in, byte i);
    static byte *key_expansion(const byte *input_key);
    static void sub_bytes(byte *state);
    static void inv_sub_bytes(byte *state);
    static void shift_rows(byte *state);
    static void inv_shift_rows(byte *state);
    static void mix_columns(byte *state);
    static void inv_mix_columns(byte *state);
    static void add_round_key(byte *state, const byte *round_key);

    byte *_encrypt(const ustring& message);
    ustring _decrypt(const byte *data);

public:
    struct encrypted_data {
        uint32 len;
        byte *bytes;
    };

    explicit aes(ustring key) {
        key = right_pad_str(key, 16);
        byte *aes_key = new byte[16];
        memcpy(aes_key, key.data(), 16);
        expanded_key = key_expansion(aes_key);
    }

    encrypted_data encrypt(const ustring& message);
    ustring decrypt(const encrypted_data &data);
};


#endif //IBZI_3_AES_H
