#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <string>
#include <algorithm>
#include <stdexcept>
using namespace std;

// === Функции утилит ===

uint32_t calculate_crc32(const vector<uint8_t>& data) {
    uint32_t crc = 0xFFFFFFFF;
    for (uint8_t byte : data) {
        crc ^= byte;
        for (int i = 0; i < 8; ++i) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            }
            else {
                crc >>= 1;
            }
        }
    }
    return crc ^ 0xFFFFFFFF;
}

void add_pkcs7_padding(vector<uint8_t>& data, size_t block_size = 8) {
    size_t pad_len = block_size - (data.size() % block_size);
    if (pad_len == 0) pad_len = block_size;
    data.resize(data.size() + pad_len, static_cast<uint8_t>(pad_len));
}

bool remove_pkcs7_padding(vector<uint8_t>& data, size_t block_size = 8) {
    if (data.empty()) return false;
    uint8_t pad_len = data.back();
    if (pad_len > block_size || pad_len == 0) {
        return false; // Некорректный padding
    }
    for (size_t i = 0; i < pad_len; ++i) {
        if (data[data.size() - 1 - i] != pad_len) {
            return false; // Некорректный padding
        }
    }
    data.resize(data.size() - pad_len);
    return true;
}

// === Класс MagmaCipher (неизменён, кроме static_cast) ===

class MagmaCipher {
private:
    uint32_t key[8];

    uint8_t s_boxes[8][16] = {
        {12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1},
        {6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15},
        {11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0},
        {12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11},
        {7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12},
        {5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0},
        {8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7},
        {1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2}
    };

    uint32_t shift_left(uint32_t value, int bits) {
        return (value << bits) | (value >> (32 - bits));
    }

    uint32_t apply_s_boxes(uint32_t value) {
        uint32_t result = 0;
        for (int i = 0; i < 8; i++) {
            uint8_t part = (value >> (4 * i)) & 0xF;
            uint8_t new_part = s_boxes[i][part];
            result |= (static_cast<uint32_t>(new_part) << (4 * i));
        }
        return result;
    }

public:
    MagmaCipher(const vector<uint8_t>& key_data) {
        if (key_data.size() < 32) {
            throw invalid_argument("Key must be at least 32 bytes");
        }
        for (int i = 0; i < 8; i++) {
            key[i] = (static_cast<uint32_t>(key_data[i * 4]) << 24) |
                (static_cast<uint32_t>(key_data[i * 4 + 1]) << 16) |
                (static_cast<uint32_t>(key_data[i * 4 + 2]) << 8) |
                static_cast<uint32_t>(key_data[i * 4 + 3]);
        }
    }

    void encrypt_block(const uint8_t* input, uint8_t* output) {
        uint32_t left = (static_cast<uint32_t>(input[0]) << 24) |
            (static_cast<uint32_t>(input[1]) << 16) |
            (static_cast<uint32_t>(input[2]) << 8) |
            static_cast<uint32_t>(input[3]);
        uint32_t right = (static_cast<uint32_t>(input[4]) << 24) |
            (static_cast<uint32_t>(input[5]) << 16) |
            (static_cast<uint32_t>(input[6]) << 8) |
            static_cast<uint32_t>(input[7]);

        for (int round = 0; round < 32; round++) {
            uint32_t temp = right;

            int key_index;
            if (round < 24) {
                key_index = round % 8;
            }
            else {
                key_index = 7 - (round % 8);
            }

            uint32_t mixed = right + key[key_index];
            uint32_t substituted = apply_s_boxes(mixed);
            uint32_t shifted = shift_left(substituted, 11);
            right = shifted ^ left;
            left = temp;
        }

        output[0] = (right >> 24) & 0xFF;
        output[1] = (right >> 16) & 0xFF;
        output[2] = (right >> 8) & 0xFF;
        output[3] = right & 0xFF;
        output[4] = (left >> 24) & 0xFF;
        output[5] = (left >> 16) & 0xFF;
        output[6] = (left >> 8) & 0xFF;
        output[7] = left & 0xFF;
    }

    void decrypt_block(const uint8_t* input, uint8_t* output) {
        encrypt_block(input, output);
    }
};

// === TripleMagmaCipher  ===

class TripleMagmaCipher {
private:
    MagmaCipher& cipher1;
    MagmaCipher& cipher2;
    MagmaCipher& cipher3;

public:
    TripleMagmaCipher(MagmaCipher& c1, MagmaCipher& c2, MagmaCipher& c3)
        : cipher1(c1), cipher2(c2), cipher3(c3) {
    }

    void encrypt_block(const uint8_t* input, uint8_t* output) {
        uint8_t temp1[8], temp2[8];
        cipher1.encrypt_block(input, temp1);
        cipher2.decrypt_block(temp1, temp2);
        cipher3.encrypt_block(temp2, output);
    }

    void decrypt_block(const uint8_t* input, uint8_t* output) {
        uint8_t temp1[8], temp2[8];
        cipher3.decrypt_block(input, temp1);
        cipher2.encrypt_block(temp1, temp2);
        cipher1.decrypt_block(temp2, output);
    }
};

// === CBC_Mode (обновлён для безопасности) ===

class CBC_Mode {
private:
    TripleMagmaCipher& cipher;
    vector<uint8_t> iv;

public:
    CBC_Mode(TripleMagmaCipher& c, const vector<uint8_t>& init_vector)
        : cipher(c), iv(init_vector) {
        if (iv.size() != 8) {
            throw invalid_argument("IV must be exactly 8 bytes");
        }
    }

    void encrypt(vector<uint8_t>& data) {
        vector<uint8_t> prev_block = iv;

        for (size_t i = 0; i < data.size(); i += 8) {
            uint8_t current_block[8] = { 0 };
            size_t block_size = min(size_t(8), data.size() - i);

            for (size_t j = 0; j < block_size; ++j) {
                current_block[j] = data[i + j] ^ prev_block[j];
            }

            uint8_t encrypted_block[8];
            cipher.encrypt_block(current_block, encrypted_block);

            for (size_t j = 0; j < block_size; ++j) {
                data[i + j] = encrypted_block[j];
            }
            // Остальные байты (если block_size < 8) — не заполняем, но PKCS#7 гарантирует block_size == 8

            prev_block.assign(encrypted_block, encrypted_block + 8);
        }
    }

    void decrypt(vector<uint8_t>& data) {
        vector<uint8_t> prev_block = iv;

        for (size_t i = 0; i < data.size(); i += 8) {
            uint8_t current_cipher_block[8] = { 0 };
            size_t block_size = min(size_t(8), data.size() - i);

            for (size_t j = 0; j < block_size; ++j) {
                current_cipher_block[j] = data[i + j];
            }

            uint8_t decrypted_block[8];
            cipher.decrypt_block(current_cipher_block, decrypted_block);

            for (size_t j = 0; j < block_size; ++j) {
                data[i + j] = decrypted_block[j] ^ prev_block[j];
            }

            prev_block.assign(current_cipher_block, current_cipher_block + 8);
        }
    }
};

// === Вспомогательные функции ввода/вывода ===

vector<uint8_t> read_file(const string& filename) {
    ifstream file(filename, ios::binary);
    if (!file) {
        throw runtime_error("Не могу открыть файл: " + filename);
    }
    file.seekg(0, ios::end);
    size_t size = static_cast<size_t>(file.tellg());
    file.seekg(0, ios::beg);

    vector<uint8_t> data(size);
    if (size > 0) {
        file.read(reinterpret_cast<char*>(data.data()), static_cast<streamsize>(size));
    }
    return data;
}

void write_file(const string& filename, const vector<uint8_t>& data) {
    ofstream file(filename, ios::binary);
    if (!file) {
        throw runtime_error("Не могу создать файл: " + filename);
    }
    if (!data.empty()) {
        file.write(reinterpret_cast<const char*>(data.data()), static_cast<streamsize>(data.size()));
    }
}

// === Основная программа ===

int main() {
    setlocale(LC_ALL, "Ru");
    cout << "ПРОГРАММА ШИФРОВАНИЯ МАГМА (ТРОЙНОЙ КЛЮЧ)" << endl;
    cout << "Режим: CBC + PKCS#7 padding" << endl;

    int choice;
    do {
        cout << "\nВыберите действие:" << endl;
        cout << "1 - Шифрование/расшифрование файла" << endl;
        cout << "0 - Выход" << endl;
        cout << "Ваш выбор: ";
        cin >> choice;

        switch (choice) {
        case 1: {
            string input_file, output_file;
            int operation;

            cout << "Введите имя файла для обработки: ";
            cin >> input_file;

            cout << "Выберите операцию (1-шифрование, 2-расшифрование): ";
            cin >> operation;

            cout << "Введите имя выходного файла: ";
            cin >> output_file;

            vector<uint8_t> key1(32, 0xAA);
            vector<uint8_t> key2(32, 0xBB);
            vector<uint8_t> key3(32, 0xCC);
            vector<uint8_t> iv(8, 0xDD);

            try {
                if (operation == 1) { // Шифрование
                    vector<uint8_t> original_data = read_file(input_file);
                    cout << "Прочитано " << original_data.size() << " байт" << endl;

                    uint32_t original_crc = calculate_crc32(original_data);

                    vector<uint8_t> data_with_crc;
                    data_with_crc.reserve(4 + original_data.size());
                    data_with_crc.push_back((original_crc >> 24) & 0xFF);
                    data_with_crc.push_back((original_crc >> 16) & 0xFF);
                    data_with_crc.push_back((original_crc >> 8) & 0xFF);
                    data_with_crc.push_back(original_crc & 0xFF);
                    data_with_crc.insert(data_with_crc.end(), original_data.begin(), original_data.end());

                    // ✅ Добавляем PKCS#7 padding ДО шифрования
                    add_pkcs7_padding(data_with_crc);
                    cout << "Размер после добавления CRC и padding: " << data_with_crc.size() << " байт" << endl;

                    MagmaCipher cipher1(key1);
                    MagmaCipher cipher2(key2);
                    MagmaCipher cipher3(key3);
                    TripleMagmaCipher triple_cipher(cipher1, cipher2, cipher3);
                    CBC_Mode cbc(triple_cipher, iv);

                    cbc.encrypt(data_with_crc);
                    write_file(output_file, data_with_crc);
                    cout << "✅ Файл успешно зашифрован!" << endl;

                }
                else if (operation == 2) { // Расшифрование
                    vector<uint8_t> encrypted_data = read_file(input_file);
                    cout << "Прочитано " << encrypted_data.size() << " байт" << endl;

                    MagmaCipher cipher1(key1);
                    MagmaCipher cipher2(key2);
                    MagmaCipher cipher3(key3);
                    TripleMagmaCipher triple_cipher(cipher1, cipher2, cipher3);
                    CBC_Mode cbc(triple_cipher, iv);

                    cbc.decrypt(encrypted_data);

                    // ✅ Удаляем PKCS#7 padding ПОСЛЕ расшифровки
                    if (!remove_pkcs7_padding(encrypted_data)) {
                        cout << "⚠️  Предупреждение: некорректный padding. Возможно, повреждён файл или неверный ключ." << endl;
                    }
                    cout << "Размер после удаления padding: " << encrypted_data.size() << " байт" << endl;

                    if (encrypted_data.size() < 4) {
                        throw runtime_error("Файл слишком мал: нет данных для CRC");
                    }

                    uint32_t expected_crc = (static_cast<uint32_t>(encrypted_data[0]) << 24) |
                        (static_cast<uint32_t>(encrypted_data[1]) << 16) |
                        (static_cast<uint32_t>(encrypted_data[2]) << 8) |
                        static_cast<uint32_t>(encrypted_data[3]);

                    vector<uint8_t> decrypted_data(encrypted_data.begin() + 4, encrypted_data.end());
                    uint32_t actual_crc = calculate_crc32(decrypted_data);

                    if (expected_crc != actual_crc) {
                        cerr << "❌ ПРЕДУПРЕЖДЕНИЕ: CRC не совпадает!" << endl;
                        cerr << "Ожидалось: 0x" << hex << expected_crc << dec << endl;
                        cerr << "Получено:  0x" << hex << actual_crc << dec << endl;
                        char ans;
                        cout << "Ключ может быть неверным. Сохранить файл в любом случае? (y/n): ";
                        cin >> ans;
                        if (ans != 'y' && ans != 'Y') {
                            cout << "Операция отменена." << endl;
                            continue;
                        }
                    }
                    else {
                        cout << "✅ CRC совпадает — данные целостны!" << endl;
                    }

                    write_file(output_file, decrypted_data);
                    cout << "✅ Файл успешно расшифрован (" << decrypted_data.size() << " байт)" << endl;

                }
                else {
                    cout << "Неверная операция. Используйте 1 или 2." << endl;
                }

            }
            catch (const exception& e) {
                cerr << "❌ Ошибка: " << e.what() << endl;
            }
            break;
        }
        case 0:
            cout << "Выход..." << endl;
            break;
        default:
            cout << "Неверный выбор!" << endl;
        }
    } while (choice != 0);

    return 0;
}