#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <stdexcept>

using namespace std;

// ������� ��� ������ ����� ����� � ������ ������
vector<unsigned char> readFile(const string& filename) {
    ifstream file(filename, ios::binary);
    if (!file.is_open()) {
        throw runtime_error("�� ������� ������� ���� ��� ������: " + filename);
    }

    // ���������� ������ �����
    file.seekg(0, ios::end);
    streamsize size = file.tellg();
    file.seekg(0, ios::beg);

    // ������� ������ ������� �������
    vector<unsigned char> buffer(size);

    // ������ ���� ����
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        throw runtime_error("������ ��� ������ �����: " + filename);
    }

    return buffer;
}

// ������� ��� ������ ������� ������ � ����
void writeFile(const string& filename, const vector<unsigned char>& data) {
    ofstream file(filename, ios::binary);
    if (!file.is_open()) {
        throw runtime_error("�� ������� ������� ���� ��� ������: " + filename);
    }

    // ���������� ���� ������
    if (!file.write(reinterpret_cast<const char*>(data.data()), data.size())) {
        throw runtime_error("������ ��� ������ �����: " + filename);
    }
}

// ������� ��� ����������/������������� �� ��������� ��������
vector<unsigned char> vigenereCipher(const vector<unsigned char>& data, const vector<unsigned char>& key, bool encrypt) {
    if (key.empty()) {
        throw invalid_argument("���� �� ����� ���� ������!");
    }

    vector<unsigned char> result(data.size());

    for (size_t i = 0; i < data.size(); ++i) {
        unsigned char byte = data[i];
        unsigned char keyByte = key[i % key.size()]; // ����������� ������������� �����

        if (encrypt) {
            // ����������: (byte + keyByte) mod 256
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

// ������� ��� �������������� ������ � ������ ������ (����)
vector<unsigned char> stringToKey(const string& keyStr) {
    vector<unsigned char> key;
    for (char c : keyStr) {
        key.push_back(static_cast<unsigned char>(c));
    }
    return key;
}

// ������� ��� �������������� ������ � ������ ������ (�������� ����)
vector<unsigned char> stringToNumericKey(const string& keyStr) {
    vector<unsigned char> key;
    size_t pos = 0;
    while (pos < keyStr.size()) {
        // ���������� �������
        while (pos < keyStr.size() && isspace(keyStr[pos])) {
            ++pos;
        }
        if (pos >= keyStr.size()) break;

        // ������ �����
        size_t endPos;
        try {
            long num = stol(keyStr.substr(pos), &endPos);
            if (num < 0 || num > 255) {
                throw out_of_range("����� ������ ���� � ��������� [0, 255]");
            }
            key.push_back(static_cast<unsigned char>(num));
            pos += endPos;
        }
        catch (...) {
            throw invalid_argument("������������ ������ ����� � �����: '" + keyStr.substr(pos) + "'");
        }
    }
    if (key.empty()) {
        throw invalid_argument("���� �� �������� �� ������ �����!");
    }
    return key;
}

int main() {
    setlocale(LC_ALL, "Ru");
    try {
        cout << "=== ������������ ������ 1: ����� ������ � ������������\n������� 4.���� �������� � �������� ������ ��� �������� ������\n������� - ������ ������� �� ������ 256 ===" << endl;

        
        string inputFilename, outputFilename, keyInput;
        char mode;

        cout << "������� ��� �������� �����: ";
        getline(cin, inputFilename);

        cout << "������� ��� ��������� �����: ";
        getline(cin, outputFilename);

        cout << "�������� ����� (S - ���������, D - ������������): ";
        cin >> mode;
        cin.ignore();

        if (mode != 'S' && mode != 's' && mode != 'D' && mode != 'd') {
            throw invalid_argument("�������� �����. ����������� S ��� D.");
        }

        cout << "������� �������� ���� (����� �� 0 �� 255, ����������� ���������): ";
        getline(cin, keyInput);

        
        vector<unsigned char> key = stringToNumericKey(keyInput);

       
        cout << "������ ����� '" << inputFilename << "'..." << endl;
        vector<unsigned char> inputData = readFile(inputFilename);

       
        cout << "���������� ��������...";
        vector<unsigned char> outputData = vigenereCipher(inputData, key, (mode == 'S' || mode == 's'));
        cout << " ������!" << endl;

        
        cout << "������ ���������� � ���� '" << outputFilename << "'..." << endl;
        writeFile(outputFilename, outputData);
        cout << "�������� ������� ���������!" << endl;

    }
    catch (const exception& e) {
        cerr << "������: " << e.what() << endl;
        return 1;
    }

    return 0;
}