#include "routeCipher.h"
#include <algorithm>
#include <cctype>
#include <locale>
#include <cwctype>
#include <iostream>
#include <vector>
#include <string>

using namespace std;

routeCipher::routeCipher(int cols)
{
    validateColumns(cols);
    columns = cols;
}

void routeCipher::validateColumns(int cols)
{
    if (cols <= 0) {
        throw route_cipher_error("Number of columns must be positive");
    }
    if (cols > 100) {
        throw route_cipher_error("Number of columns is too large");
    }
}

std::wstring routeCipher::getValidOpenText(const std::wstring& s)
{
    if (s.empty()) {
        throw route_cipher_error("Empty open text");
    }
    
    std::wstring result;
    std::locale loc("ru_RU.UTF-8");
    
    for (wchar_t c : s) {
        if (iswalpha(c) || c == L' ') {
            if (iswalpha(c)) {
                c = towupper(c);
            }
            result += c;
        }
    }
    
    std::wstring textWithoutSpaces;
    for (wchar_t c : result) {
        if (c != L' ') {
            textWithoutSpaces += c;
        }
    }
    
    if (textWithoutSpaces.empty()) {
        throw route_cipher_error("Open text contains no valid letters");
    }
    
    return textWithoutSpaces;
}

std::wstring routeCipher::getValidCipherText(const std::wstring& s)
{
    if (s.empty()) {
        throw route_cipher_error("Empty cipher text");
    }
    
    for (wchar_t c : s) {
        if (!iswalpha(c)) {
            throw route_cipher_error("Cipher text must contain only letters");
        }
        if (!iswupper(c)) {
            throw route_cipher_error("Cipher text must be in uppercase");
        }
    }
    
    return s;
}

// Шифрование - ПРАВИЛЬНЫЙ алгоритм
std::wstring routeCipher::encrypt(const std::wstring& text)
{
    std::wstring prepared = getValidOpenText(text);
    int len = prepared.length();
    
    if (len == 0) {
        throw route_cipher_error("No valid text to encrypt");
    }
    
    // Вычисляем количество строк
    int rows = (len + columns - 1) / columns;
    
    // Количество пустых ячеек
    int empty_cells = rows * columns - len;
    
    // Создаем таблицу
    vector<vector<wchar_t>> table(rows, vector<wchar_t>(columns, L' '));
    
    // Заполняем таблицу по строкам
    int index = 0;
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < columns; j++) {
            if (index < len) {
                table[i][j] = prepared[index++];
            }
        }
    }
    
    // Читаем по столбцам справа налево
    wstring result;
    
    // Ключевой момент: пустые ячейки находятся в ПОСЛЕДНЕЙ СТРОКЕ
    // При чтении столбцов справа налево, мы должны пропускать пустые ячейки
    
    for (int j = columns - 1; j >= 0; j--) {
        // Для каждого столбца определяем, нужно ли читать последнюю строку
        bool read_last_row = true;
        
        // Пустые ячейки находятся в последней строке
        // Они распределяются с ПРАВОГО КРАЯ таблицы
        // То есть в правых столбцах
        
        // Вычисляем: сколько ячеек в последней строке пустые
        int empty_in_last_row = empty_cells;
        
        // Если этот столбец находится среди тех, где в последней строке пусто
        // Считаем с правого края
        if (j >= columns - empty_in_last_row) {
            read_last_row = false;
        }
        
        // Читаем столбец
        for (int i = 0; i < rows; i++) {
            // Если это последняя строка и мы ее не читаем - пропускаем
            if (i == rows - 1 && !read_last_row) {
                continue;
            }
            
            if (table[i][j] != L' ') {
                result += table[i][j];
            }
        }
    }
    
    return result;
}

// Дешифрование - ПРАВИЛЬНЫЙ алгоритм
std::wstring routeCipher::decrypt(const std::wstring& text)
{
    std::wstring prepared = getValidCipherText(text);
    int len = prepared.length();
    
    if (len == 0) {
        throw route_cipher_error("No valid text to decrypt");
    }
    
    // Вычисляем количество строк
    int rows = (len + columns - 1) / columns;
    
    // Количество пустых ячеек
    int empty_cells = rows * columns - len;
    
    // Создаем таблицу
    vector<vector<wchar_t>> table(rows, vector<wchar_t>(columns, L' '));
    
    // Заполняем таблицу по столбцам справа налево
    int index = 0;
    
    for (int j = columns - 1; j >= 0; j--) {
        // Определяем, нужно ли заполнять последнюю строку в этом столбце
        bool fill_last_row = true;
        
        // Пустые ячейки находятся в последней строке ПРАВЫХ столбцов
        // (потому что при чтении мы начинаем справа)
        if (j >= columns - empty_cells) {
            fill_last_row = false;
        }
        
        // Заполняем столбец
        for (int i = 0; i < rows; i++) {
            // Если это последняя строка и мы ее не заполняем - пропускаем
            if (i == rows - 1 && !fill_last_row) {
                continue;
            }
            
            if (index < len) {
                table[i][j] = prepared[index++];
            }
        }
    }
    
    // Читаем по строкам
    wstring result;
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < columns; j++) {
            if (table[i][j] != L' ') {
                result += table[i][j];
            }
        }
    }
    
    return result;
}