//
// Created by Admin on 21.05.2021.
//

#include <iostream>
#include <string>
#include <cassert>

#include "utils.h"
#include "aes.h"

int main() {

    system("chcp 65001");


    auto messages = {
            ustr("test message"),
            ustr("very long message, longer than 16 symbols"),
            ustr("Сообщение на русском"),
            ustr("qwert12"),
    };
    // Строка ключа шифрования
    ustring aes_key = ustr("random key string");
    // Объект-шифратор
    aes aes(aes_key);

    // Пробегаемся по списку сообщений
    for (const auto &message : messages) {
        // Шифруем сообщение
        auto enc_msg = aes.encrypt(message);
        // Дешифруем и обрезаем по длине
        auto dec_msg = aes.decrypt(enc_msg);

        assert(message == dec_msg.substr(0, message.length()));


        std::cout << "Оригинальное сообщение: " << cpstr(message) << std::endl;
        std::cout << "Зашифрованное сообщение: ";
        print_hex(enc_msg.bytes, enc_msg.len);
        std::cout << "Дешифрованное сообщение: " << cpstr(dec_msg) << std::endl;
        std::cout << std::endl;
    }


    return 0;
}
