#pragma once
#include <vector>
#include <string>
#include <map>
#include <locale>
#include <stdexcept>
#include <algorithm>

class cipher_error : public std::invalid_argument {
public:
    explicit cipher_error(const std::string& what_arg) :
        std::invalid_argument(what_arg) {}
    explicit cipher_error(const char* what_arg) :
        std::invalid_argument(what_arg) {}
};

class modAlphaCipher
{
private:
    std::wstring numAlpha = L"АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ";
    std::map<wchar_t, int> alphaNum;
    std::vector<int> key;

    std::vector<int> convert(const std::wstring& s);
    std::wstring convert(const std::vector<int>& v);
    
    // Методы валидации
    std::wstring getValidKey(const std::wstring& s);
    std::wstring getValidOpenText(const std::wstring& s);
    std::wstring getValidCipherText(const std::wstring& s);

public:
    modAlphaCipher() = delete;
    modAlphaCipher(const std::wstring& skey);
    
    std::wstring encrypt(const std::wstring& open_text);
    std::wstring decrypt(const std::wstring& cipher_text);
};