//
// Created by Admin on 21.05.2021.
//

#include "aes.h"

/*
 * Проворачивает 4 байта in влево, меняет местами старшие 8 с младшими 8 байтами
 * потом умножает на rcon[i]
 *
 * in - проворачиваемые байты
 * i - индекс в RCon для умножения
 */
void aes::key_expansion_core(byte *in, byte i) {
    auto q = (uint16 *) in;
    // Left rotate bytes
    *q = (*q >> 8 | ((*q & 0xff) << 24));

    in[0] = s_box[in[0]];
    in[1] = s_box[in[1]];
    in[2] = s_box[in[2]];
    in[3] = s_box[in[3]];

    // XOR с RCon
    in[0] ^= rcon[i];
}

/*
 * Функция принимает 16 байтный ключ и расширяет его до 176 байтов
 */
byte *aes::key_expansion(const byte *input_key) {
    byte *expanded_key = new byte[176];

    // Set first 16 bytes to input_key
    for (int i = 0; i < 16; i++) {
        expanded_key[i] = input_key[i];
    }

    unsigned int bytes_generated = 16;
    int rcon_iteration = 1;
    byte temp[4];

    // Generate the next 160 bytes
    while (bytes_generated < 176) {
        // Read 4 bytes for the core
        for (int i = 0; i < 4; i++) {
            temp[i] = expanded_key[i + bytes_generated - 4];
        }

        // Perform the core once for each 16 byte key
        if (bytes_generated % 16 == 0) {
            key_expansion_core(temp, rcon_iteration++);
        }

        // XOR temp with [bytes_generated-16], and store in expanded_keys
        for (byte a : temp) {
            expanded_key[bytes_generated] = expanded_key[bytes_generated - 16] ^ a;
            bytes_generated++;
        }
    }

    return expanded_key;
}

/*
 * Заменяет байты в матрице state на значения из S-Box
 */
void aes::sub_bytes(byte *state) {
    for (int i = 0; i < 16; i++) {
        state[i] = s_box[state[i]];
    }
}

/*
 * Заменяет байты в матрице state на значения из обратного InvS-Box
 */
void aes::inv_sub_bytes(byte *state) {
    for (int i = 0; i < 16; i++) {
        state[i] = inv_s_box[state[i]];
    }
}

/*
 * Сдвигает строки в матрице
 *
 * Строка 1 - не сдвигается.
 * Строка 2 - сдвигается влево на 1.
 * Строка 3 - сдвигается влево на 2.
 * Строка 4 - сдвигается влево на 3.
 */
void aes::shift_rows(byte *state) {
    byte tmp[16];

    // Не сдвигаем (idx = idx)
    tmp[0] = state[0];
    tmp[4] = state[4];
    tmp[8] = state[8];
    tmp[12] = state[12];

    // Сдвигаем на единицу (idx = (idx + 4) % 16)
    tmp[1] = state[5];
    tmp[5] = state[9];
    tmp[9] = state[13];
    tmp[13] = state[1];

    // Сдвигаем на два (idx = (idx +/- 8) % 16)
    tmp[2] = state[10];
    tmp[6] = state[14];
    tmp[10] = state[2];
    tmp[14] = state[6];

    // Сдвигаем на три (idx = (idx - 4) % 16)
    tmp[3] = state[15];
    tmp[7] = state[3];
    tmp[11] = state[7];
    tmp[15] = state[11];

    for (int i = 0; i < 16; i++) {
        state[i] = tmp[i];
    }
}

/*
 * Сдвигает строки в матрице
 *
 * Строка 1 - не сдвигается.
 * Строка 2 - сдвигается вправо на 1.
 * Строка 3 - сдвигается вправо на 2.
 * Строка 4 - сдвигается вправо на 3.
 */
void aes::inv_shift_rows(byte *state) {
    byte tmp[16];

    // Не сдвигаем (idx = idx)
    tmp[0] = state[0];
    tmp[4] = state[4];
    tmp[8] = state[8];
    tmp[12] = state[12];

    // Сдвигаем на единицу (idx = (idx - 4) % 16)
    tmp[1] = state[13];
    tmp[5] = state[1];
    tmp[9] = state[5];
    tmp[13] = state[9];

    // Сдвигаем на два (idx = (idx +/- 8) % 16)
    tmp[2] = state[10];
    tmp[6] = state[14];
    tmp[10] = state[2];
    tmp[14] = state[6];

    // сдвигаем на три (idx = (idx + 4) % 16)
    tmp[3] = state[7];
    tmp[7] = state[11];
    tmp[11] = state[15];
    tmp[15] = state[3];

    for (int i = 0; i < 16; i++) {
        state[i] = tmp[i];
    }
}

/*
 * Умножение по GF(256) матрицы состояния state
 *
 * Как-то так:
 *     d_0 = (2*b_0) + (3*b_1) + (1*b_2) + (1*b_3)
 *     d_1 = (1*b_0) + (2*b_1) + (3*b_2) + (1*b_3)
 *     d_2 = (1*b_0) + (1*b_1) + (2*b_2) + (3*b_3)
 *     d_3 = (3*b_0) + (1*b_1) + (1*b_2) + (2*b_3)
 *
 * https://en.wikipedia.org/wiki/Rijndael_MixColumns
 */
void aes::mix_columns(byte *state) {
    byte tmp[16];

    tmp[0] = (byte) (mul2[state[0]] ^ mul3[state[1]] ^ state[2] ^ state[3]);
    tmp[1] = (byte) (state[0] ^ mul2[state[1]] ^ mul3[state[2]] ^ state[3]);
    tmp[2] = (byte) (state[0] ^ state[1] ^ mul2[state[2]] ^ mul3[state[3]]);
    tmp[3] = (byte) (mul3[state[0]] ^ state[1] ^ state[2] ^ mul2[state[3]]);

    tmp[4] = (byte) (mul2[state[4]] ^ mul3[state[5]] ^ state[6] ^ state[7]);
    tmp[5] = (byte) (state[4] ^ mul2[state[5]] ^ mul3[state[6]] ^ state[7]);
    tmp[6] = (byte) (state[4] ^ state[5] ^ mul2[state[6]] ^ mul3[state[7]]);
    tmp[7] = (byte) (mul3[state[4]] ^ state[5] ^ state[6] ^ mul2[state[7]]);

    tmp[8] = (byte) (mul2[state[8]] ^ mul3[state[9]] ^ state[10] ^ state[11]);
    tmp[9] = (byte) (state[8] ^ mul2[state[9]] ^ mul3[state[10]] ^ state[11]);
    tmp[10] = (byte) (state[8] ^ state[9] ^ mul2[state[10]] ^ mul3[state[11]]);
    tmp[11] = (byte) (mul3[state[8]] ^ state[9] ^ state[10] ^ mul2[state[11]]);

    tmp[12] = (byte) (mul2[state[12]] ^ mul3[state[13]] ^ state[14] ^ state[15]);
    tmp[13] = (byte) (state[12] ^ mul2[state[13]] ^ mul3[state[14]] ^ state[15]);
    tmp[14] = (byte) (state[12] ^ state[13] ^ mul2[state[14]] ^ mul3[state[15]]);
    tmp[15] = (byte) (mul3[state[12]] ^ state[13] ^ state[14] ^ mul2[state[15]]);

    for (int i = 0; i < 16; i++) {
        state[i] = tmp[i];
    }
}

/*
 * Обратная операция для mix_columns
 *
 * Как-то так?
 *     d_0 = (14*b_0) + (11*b_1) + (13*b_2) + ( 9*b_3)
 *     d_1 = ( 9*b_0) + (14*b_1) + (11*b_2) + (13*b_3)
 *     d_2 = (13*b_0) + ( 9*b_1) + (14*b_2) + (11*b_3)
 *     d_3 = (11*b_0) + (13*b_1) + ( 9*b_2) + (14*b_3)
 *
 * https://en.wikipedia.org/wiki/Rijndael_MixColumns
 */
void aes::inv_mix_columns(byte *state) {
    byte tmp[16];

    tmp[0] = (byte) (mul14[state[0]] ^ mul11[state[1]] ^ mul13[state[2]] ^ mul9[state[3]]);
    tmp[1] = (byte) (mul9[state[0]] ^ mul14[state[1]] ^ mul11[state[2]] ^ mul13[state[3]]);
    tmp[2] = (byte) (mul13[state[0]] ^ mul9[state[1]] ^ mul14[state[2]] ^ mul11[state[3]]);
    tmp[3] = (byte) (mul11[state[0]] ^ mul13[state[1]] ^ mul9[state[2]] ^ mul14[state[3]]);

    tmp[4] = (byte) (mul14[state[4]] ^ mul11[state[5]] ^ mul13[state[6]] ^ mul9[state[7]]);
    tmp[5] = (byte) (mul9[state[4]] ^ mul14[state[5]] ^ mul11[state[6]] ^ mul13[state[7]]);
    tmp[6] = (byte) (mul13[state[4]] ^ mul9[state[5]] ^ mul14[state[6]] ^ mul11[state[7]]);
    tmp[7] = (byte) (mul11[state[4]] ^ mul13[state[5]] ^ mul9[state[6]] ^ mul14[state[7]]);

    tmp[8] = (byte) (mul14[state[8]] ^ mul11[state[9]] ^ mul13[state[10]] ^ mul9[state[11]]);
    tmp[9] = (byte) (mul9[state[8]] ^ mul14[state[9]] ^ mul11[state[10]] ^ mul13[state[11]]);
    tmp[10] = (byte) (mul13[state[8]] ^ mul9[state[9]] ^ mul14[state[10]] ^ mul11[state[11]]);
    tmp[11] = (byte) (mul11[state[8]] ^ mul13[state[9]] ^ mul9[state[10]] ^ mul14[state[11]]);

    tmp[12] = (byte) (mul14[state[12]] ^ mul11[state[13]] ^ mul13[state[14]] ^ mul9[state[15]]);
    tmp[13] = (byte) (mul9[state[12]] ^ mul14[state[13]] ^ mul11[state[14]] ^ mul13[state[15]]);
    tmp[14] = (byte) (mul13[state[12]] ^ mul9[state[13]] ^ mul14[state[14]] ^ mul11[state[15]]);
    tmp[15] = (byte) (mul11[state[12]] ^ mul13[state[13]] ^ mul9[state[14]] ^ mul14[state[15]]);

    for (int i = 0; i < 16; i++) {
        state[i] = tmp[i];
    }
}

/*
 * С помощью XOR вмешивает в матрицу состояния state раундовый ключ round_key
 */
void aes::add_round_key(byte *state, const byte *round_key) {
    for (int i = 0; i < 16; i++) {
        state[i] ^= round_key[i];
    }
}

/*
 * Функция шифрования.
 * Реализует AES-128 ECB шифрование.
 *
 * Как:
 *     На первом раунде:
 *         В первые 16 байт вмешиваем раундовый ключ (282)
 *
 *     Далее девять раундов:
 *         Делаем замену из S-Box (285)
 *         Сдвиг влево (286)
 *         Умножение по полю GF(256) (287)
 *         Вмешивание раундового ключа (288)
 *
 *     Последний раунд:
 *         Делаем замену из S-Box (291)
 *         Сдвиг влево (292)
 *         Вмешивание раундового ключа (293)
 */
byte *aes::_encrypt(const ustring &message) {
    byte state[16];

    for (int i = 0; i < 16; i++) {
        state[i] = message[i];
    }

    const unsigned int round_cnt = 9;
    add_round_key(state, this->expanded_key);

    for (int i = 0; i < round_cnt; i++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, this->expanded_key + (16 * (i + 1)));
    }

    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, this->expanded_key + 160);

    byte *enc_msg = new byte[16];
    memcpy(enc_msg, state, 16);
    return enc_msg;
}

/*
 * Функция дешифрования.
 * Реализует дешифрование AES-128 ECB.
 *
 * Как:
 *     На первом раунде:
 *         В первые 16 байт вмешиваем раундовый ключ (327)
 *
 *     Далее девять раундов:
 *         Сдвиг вправо (330)
 *         Делаем замену из обратного InvS-Box (331)
 *         Вмешивание раундового ключа (332)
 *         Обратное умножение по полю GF(256) (333)
 *
 *     Последний раунд:
 *         Сдвиг вправо (336)
 *         Делаем замену из обратного InvS-Box (337)
 *         Вмешивание раундового ключа (338)
 */
ustring aes::_decrypt(const byte *data) {
    byte state[16];

    for (int i = 0; i < 16; i++) {
        state[i] = data[i];
    }

    const int round_cnt = 9;
    add_round_key(state, this->expanded_key + 160);

    for (int i = round_cnt; i > 0; i--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, this->expanded_key + (16 * i));
        inv_mix_columns(state);
    }

    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, this->expanded_key);

    ustring dec_msg;
    for (byte i : state) {
        dec_msg += i;
    }
    return dec_msg;
}

/*
 * Функция шифрования сообщения, использует _encrypt(...) (см. выше)
 */
aes::encrypted_data aes::encrypt(const ustring &message) {
    auto m_cp = right_pad_str_empty(message, round_up((int) message.length(), 16));
    byte *enc_bytes = new byte[m_cp.length()]{0};
    for (int i = 0; i < m_cp.length() / 16; i++) {
        auto substr = m_cp.substr(16 * i, 16 * (i + 1));
        memcpy(enc_bytes + (16 * i), this->_encrypt(substr), 16);
    }
    return {
            m_cp.length(), enc_bytes
    };
}

/*
 * Функция дешифрования сообщения, использует _decrypt(...) (см. выше)
 */
ustring aes::decrypt(const encrypted_data &data) {
    ustring out;

    for (uint32 i = 0; i < data.len; i++) {
        out += this->_decrypt(data.bytes + (16 * i));
    }
    out = out.substr(0, data.len);

    return out;
}
