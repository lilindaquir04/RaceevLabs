#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <stdexcept>

using namespace std;

// Функция для чтения всего файла в вектор байтов
vector<unsigned char> readFile(const string& filename) {
    ifstream file(filename, ios::binary);
    if (!file.is_open()) {
        throw runtime_error("Не удалось открыть файл для чтения: " + filename);
    }

    // Определяем размер файла
    file.seekg(0, ios::end);
    streamsize size = file.tellg();
    file.seekg(0, ios::beg);

    // Создаем вектор нужного размера
    vector<unsigned char> buffer(size);

    // Читаем весь файл
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        throw runtime_error("Ошибка при чтении файла: " + filename);
    }

    return buffer;
}

// Функция для записи вектора байтов в файл
void writeFile(const string& filename, const vector<unsigned char>& data) {
    ofstream file(filename, ios::binary);
    if (!file.is_open()) {
        throw runtime_error("Не удалось открыть файл для записи: " + filename);
    }

    // Записываем весь вектор
    if (!file.write(reinterpret_cast<const char*>(data.data()), data.size())) {
        throw runtime_error("Ошибка при записи файла: " + filename);
    }
}

// Функция для шифрования/расшифрования по алгоритму Виженера
vector<unsigned char> vigenereCipher(const vector<unsigned char>& data, const vector<unsigned char>& key, bool encrypt) {
    if (key.empty()) {
        throw invalid_argument("Ключ не может быть пустым!");
    }

    vector<unsigned char> result(data.size());

    for (size_t i = 0; i < data.size(); ++i) {
        unsigned char byte = data[i];
        unsigned char keyByte = key[i % key.size()]; // Циклическое использование ключа

        if (encrypt) {
            // Шифрование: (byte + keyByte) mod 256
            result[i] = (byte + keyByte) % 256;
        }
        else {
            
            int temp = static_cast<int>(byte) - static_cast<int>(keyByte);
            if (temp < 0) {
                temp += 256;
            }
            result[i] = static_cast<unsigned char>(temp % 256);
        }
    }

    return result;
}

// Функция для преобразования строки в вектор байтов (ключ)
vector<unsigned char> stringToKey(const string& keyStr) {
    vector<unsigned char> key;
    for (char c : keyStr) {
        key.push_back(static_cast<unsigned char>(c));
    }
    return key;
}

// Функция для преобразования строки в вектор байтов (числовой ключ)
vector<unsigned char> stringToNumericKey(const string& keyStr) {
    vector<unsigned char> key;
    size_t pos = 0;
    while (pos < keyStr.size()) {
        // Пропускаем пробелы
        while (pos < keyStr.size() && isspace(keyStr[pos])) {
            ++pos;
        }
        if (pos >= keyStr.size()) break;

        // Парсим число
        size_t endPos;
        try {
            long num = stol(keyStr.substr(pos), &endPos);
            if (num < 0 || num > 255) {
                throw out_of_range("Число должно быть в диапазоне [0, 255]");
            }
            key.push_back(static_cast<unsigned char>(num));
            pos += endPos;
        }
        catch (...) {
            throw invalid_argument("Некорректный формат числа в ключе: '" + keyStr.substr(pos) + "'");
        }
    }
    if (key.empty()) {
        throw invalid_argument("Ключ не содержит ни одного числа!");
    }
    return key;
}

int main() {
    setlocale(LC_ALL, "Ru");
    try {
        cout << "=== Лабораторная работа 1: Шифры замены и перестановки\nВариант 4.Шифр Виженера с числовым ключом для двоичных файлов\nАлфавит - кольцо вычетов по модулю 256 ===" << endl;

        
        string inputFilename, outputFilename, keyInput;
        char mode;

        cout << "Введите имя входного файла: ";
        getline(cin, inputFilename);

        cout << "Введите имя выходного файла: ";
        getline(cin, outputFilename);

        cout << "Выберите режим (S - шифровать, D - расшифровать): ";
        cin >> mode;
        cin.ignore();

        if (mode != 'S' && mode != 's' && mode != 'D' && mode != 'd') {
            throw invalid_argument("Неверный режим. Используйте S или D.");
        }

        cout << "Введите числовой ключ (числа от 0 до 255, разделенные пробелами): ";
        getline(cin, keyInput);

        
        vector<unsigned char> key = stringToNumericKey(keyInput);

       
        cout << "Чтение файла '" << inputFilename << "'..." << endl;
        vector<unsigned char> inputData = readFile(inputFilename);

       
        cout << "Выполнение операции...";
        vector<unsigned char> outputData = vigenereCipher(inputData, key, (mode == 'S' || mode == 's'));
        cout << " Готово!" << endl;

        
        cout << "Запись результата в файл '" << outputFilename << "'..." << endl;
        writeFile(outputFilename, outputData);
        cout << "Операция успешно завершена!" << endl;

    }
    catch (const exception& e) {
        cerr << "Ошибка: " << e.what() << endl;
        return 1;
    }

    return 0;
}