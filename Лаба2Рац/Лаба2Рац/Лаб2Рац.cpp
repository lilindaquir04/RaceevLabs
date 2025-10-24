#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <string>
#include <algorithm>
using namespace std;

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
            result |= (uint32_t(new_part) << (4 * i));
        }
        return result;
    }

public:
    MagmaCipher(const vector<uint8_t>& key_data) {
        for (int i = 0; i < 8; i++) {
            key[i] = (uint32_t(key_data[i * 4]) << 24) |
                (uint32_t(key_data[i * 4 + 1]) << 16) |
                (uint32_t(key_data[i * 4 + 2]) << 8) |
                (uint32_t(key_data[i * 4 + 3]));
        }
    }

    void encrypt_block(const uint8_t* input, uint8_t* output) {
        uint32_t left = (uint32_t(input[0]) << 24) | (uint32_t(input[1]) << 16) |
            (uint32_t(input[2]) << 8) | uint32_t(input[3]);
        uint32_t right = (uint32_t(input[4]) << 24) | (uint32_t(input[5]) << 16) |
            (uint32_t(input[6]) << 8) | uint32_t(input[7]);

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

class CFB_Mode {
private:
    MagmaCipher& cipher;
    vector<uint8_t> iv;

public:
    CFB_Mode(MagmaCipher& c, const vector<uint8_t>& init_vector)
        : cipher(c), iv(init_vector) {
    }

    void encrypt(vector<uint8_t>& data) {
        vector<uint8_t> feedback = iv;

        for (size_t i = 0; i < data.size(); i += 8) {
            uint8_t encrypted_feedback[8];
            cipher.encrypt_block(feedback.data(), encrypted_feedback);

            size_t block_size = min(size_t(8), data.size() - i);

            for (size_t j = 0; j < block_size; j++) {
                data[i + j] ^= encrypted_feedback[j];
            }

            copy(data.begin() + i, data.begin() + i + block_size, feedback.begin());

            if (block_size < 8) {
                fill(feedback.begin() + block_size, feedback.end(), 0);
            }
        }
    }

    void decrypt(vector<uint8_t>& data) {
        vector<uint8_t> feedback = iv;

        for (size_t i = 0; i < data.size(); i += 8) {
            uint8_t encrypted_feedback[8];
            cipher.encrypt_block(feedback.data(), encrypted_feedback);

            size_t block_size = min(size_t(8), data.size() - i);

            vector<uint8_t> original_block(data.begin() + i, data.begin() + i + block_size);

            for (size_t j = 0; j < block_size; j++) {
                data[i + j] ^= encrypted_feedback[j];
            }

            copy(original_block.begin(), original_block.end(), feedback.begin());

            if (block_size < 8) {
                fill(feedback.begin() + block_size, feedback.end(), 0);
            }
        }
    }
};

vector<uint8_t> read_file(const string& filename) {
    ifstream file(filename, ios::binary);
    if (!file) {
        throw runtime_error("Не могу открыть файл: " + filename);
    }

    file.seekg(0, ios::end);
    size_t size = file.tellg();
    file.seekg(0, ios::beg);

    vector<uint8_t> data(size);
    file.read(reinterpret_cast<char*>(data.data()), size);

    return data;
}

void write_file(const string& filename, const vector<uint8_t>& data) {
    ofstream file(filename, ios::binary);
    if (!file) {
        throw runtime_error("Не могу создать файл: " + filename);
    }

    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

int main() {
    setlocale(LC_ALL, "Ru");
    cout << "ПРОГРАММА ШИФРОВАНИЯ МАГМА" << endl;
    cout << "Режим: CFB (Обратная связь по шифртексту)" << endl;

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

            vector<uint8_t> key(32, 0xAA);
            vector<uint8_t> iv(8, 0xBB);

            try {
                vector<uint8_t> data = read_file(input_file);
                cout << "Прочитано " << data.size() << " байт" << endl;

                MagmaCipher cipher(key);
                CFB_Mode cfb(cipher, iv);

                if (operation == 1) {
                    cfb.encrypt(data);
                    cout << "Файл зашифрован!" << endl;
                }
                else {
                    cfb.decrypt(data);
                    cout << "Файл расшифрован!" << endl;
                }

                write_file(output_file, data);
                cout << "Результат сохранен в: " << output_file << endl;

            }
            catch (const exception& e) {
                cout << "Ошибка: " << e.what() << endl;
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