//
// Created by Admin on 21.05.2021.
//

#ifndef IBZI_3_UTILS_H
#define IBZI_3_UTILS_H

#include <vector>
#include <functional>
#include <cstring>

typedef unsigned char byte;
typedef unsigned int uint16;
typedef unsigned long long uint32;
typedef std::basic_string<byte> ustring;

/*
 * Добивает строку справа её же копиями
 * Используется для расширения текстового ключа
 */
inline ustring right_pad_str(ustring str, uint16 len) {
    ustring padded_str(str.begin(), str.end());

    while (padded_str.length() < len) {
        padded_str += padded_str;
    }
    padded_str = padded_str.substr(0, len);

    return padded_str;
}

/*
 * Добивает строку справа пробелами
 * Используется для расширения блока сообщения
 */
inline ustring right_pad_str_empty(ustring str, uint16 len) {
    ustring padded_str(str.begin(), str.end());

    while (padded_str.length() < len) {
        padded_str += ' ';
    }

    return padded_str;
}

/*
 * Выводит байты в шестнадцатеричном представлении
 */
inline void print_hex(const byte *msg, uint32 len) {
    for (uint32 i = 0; i < len; i++) {
        printf("%02x ", msg[i]);
    }
    printf("\n");
}

/*
 * Округление num вверх до ближайшего моножителя mul
 */
inline int round_up(int num, int mul) {
    if (mul == 0) {
        return num;
    }

    int remainder = num % mul;
    if (remainder == 0) {
        return num;
    }

    return num + mul - remainder;
}

/*
 * Функция превращает std::string в нашу ustring
 */
inline ustring ustr(std::string cp_str) {
    return ustring(cp_str.begin(), cp_str.end());
}

/*
 * Функция превращает нашу ustring в std::string
 */
inline std::string cpstr(ustring u_str) {
    return std::string(u_str.begin(), u_str.end());
}

#endif //IBZI_3_UTILS_H
