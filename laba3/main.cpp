#include <UnitTest++/UnitTest++.h>
#include "modAlphaCipher.h"
#include <locale>
#include <iostream>
#include <codecvt>
#include <string>

using namespace std;

// Функции для преобразования wstring <-> string
string wstring_to_string(const wstring& wstr) {
    wstring_convert<codecvt_utf8<wchar_t>> converter;
    return converter.to_bytes(wstr);
}

wstring string_to_wstring(const string& str) {
    wstring_convert<codecvt_utf8<wchar_t>> converter;
    return converter.from_bytes(str);
}

// Глобальная настройка локали
struct LocaleSetup {
    LocaleSetup() {
        std::locale::global(std::locale("ru_RU.UTF-8"));
    }
};

LocaleSetup localeSetup;

// ==================== ТЕСТЫ ДЛЯ КОНСТРУКТОРА ====================

SUITE(KeyTest)
{
    TEST(ValidKey) {
        // 1.1 Верный ключ
        CHECK_EQUAL("БВГБВ", wstring_to_string(modAlphaCipher(L"БВГ").encrypt(L"ААААА")));
    }
    
    TEST(LongKey) {
        // 1.2 Ключ длиннее сообщения
        CHECK_EQUAL("БВГДЕ", wstring_to_string(modAlphaCipher(L"БВГДЕЁЖЗИЙК").encrypt(L"ААААА")));
    }
    
    TEST(LowCaseKey) {
        // 1.3 В ключе строчные буквы
        CHECK_EQUAL("БВГБВ", wstring_to_string(modAlphaCipher(L"бвг").encrypt(L"ААААА")));
    }
    
    TEST(DigitsInKey) {
        // 1.4 В ключе цифры
        CHECK_THROW(modAlphaCipher(L"Б1"), cipher_error);
    }
    
    TEST(PunctuationInKey) {
        // 1.5 В ключе знаки препинания
        CHECK_THROW(modAlphaCipher(L"Б,В"), cipher_error);
    }
    
    TEST(WhitespaceInKey) {
        // 1.6 В ключе пробелы
        CHECK_THROW(modAlphaCipher(L"Б В"), cipher_error);
    }
    
    TEST(EmptyKey) {
        // 1.7 Пустой ключ
        CHECK_THROW(modAlphaCipher(L""), cipher_error);
    }
    
    TEST(WeakKey) {
        // 1.8 Вырожденный ключ
        CHECK_THROW(modAlphaCipher(L"ААА"), cipher_error);
    }
}

// ==================== ТЕСТЫ ДЛЯ МЕТОДА ENCRYPT ====================

struct KeyB_fixture {
    modAlphaCipher* p;
    
    KeyB_fixture() {
        p = new modAlphaCipher(L"Б"); // Ключ "Б" - сдвиг на 1
    }
    
    ~KeyB_fixture() {
        delete p;
    }
};

SUITE(EncryptTest)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        // 2.1 Строка из прописных букв
        string expected = "БВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯА";
        string actual = wstring_to_string(p->encrypt(L"АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"));
        CHECK_EQUAL(expected, actual);
    }
    
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        // 2.2 Строка из строчных букв
        string expected = "БВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯА";
        string actual = wstring_to_string(p->encrypt(L"абвгдеёжзийклмнопрстуфхцчшщъыьэюя"));
        CHECK_EQUAL(expected, actual);
    }
    
    TEST_FIXTURE(KeyB_fixture, StringWithWhitespaceAndPunct) {
        // 2.3 Строка с пробелами и знаками препинания
        string expected = "БВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯА";
        string actual = wstring_to_string(p->encrypt(L"А,Б.В!Г?Д Е-Ё:Ж;З (И)Й К+Л=М Н*О П/Р С%Т У^Ф Х&Ц Ч|Ш Щ~Ъ Ы`Ь Э'Ю \"Я\""));
        CHECK_EQUAL(expected, actual);
    }
    
    TEST_FIXTURE(KeyB_fixture, StringWithNumbers) {
        // 2.4 Строка с цифрами
        CHECK_EQUAL("БВГ", wstring_to_string(p->encrypt(L"АБВ123")));
    }
    
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        // 2.5 Пустой текст
        CHECK_THROW(p->encrypt(L""), cipher_error);
    }
    
    TEST_FIXTURE(KeyB_fixture, NoAlphaString) {
        // 2.6 Нет букв
        CHECK_THROW(p->encrypt(L"1234+8765=9999"), cipher_error);
    }
    
    TEST(MaxShiftKey) {
        // 2.7 Максимальный сдвиг
        modAlphaCipher cipher(L"Я");
        string expected = "ЯАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮ";
        string actual = wstring_to_string(cipher.encrypt(L"АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"));
        CHECK_EQUAL(expected, actual);
    }
}

// ==================== ТЕСТЫ ДЛЯ МЕТОДА DECRYPT ====================

SUITE(DecryptTest)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        // 3.1 Строка из прописных букв
        string expected = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ";
        string actual = wstring_to_string(p->decrypt(L"БВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯА"));
        CHECK_EQUAL(expected, actual);
    }
    
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        // 3.2 Строчные буквы в шифротексте
        CHECK_THROW(p->decrypt(L"бВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯА"), cipher_error);
    }
    
    TEST_FIXTURE(KeyB_fixture, WhitespaceString) {
        // 3.3 Пробелы в шифротексте
        CHECK_THROW(p->decrypt(L"БВГ ДЕЁ ЖЗИ ЙКЛ МНО ПРС ТУФ ХЦЧ ШЩЪ ЫЬЭ ЮЯА"), cipher_error);
    }
    
    TEST_FIXTURE(KeyB_fixture, DigitsString) {
        // 3.4 Цифры в шифротексте
        CHECK_THROW(p->decrypt(L"БВГ123ДЕЁ456ЖЗИ"), cipher_error);
    }
    
    TEST_FIXTURE(KeyB_fixture, PunctString) {
        // 3.5 Знаки препинания в шифротексте
        CHECK_THROW(p->decrypt(L"Б,В.Г!Д?Е -Ё:Ж ;З (И) Й+К=Л М*Н О/П Р%С Т^У Ф&Х Ц|Ч Ш~Щ Ъ`Ы Ь'Э Ю\"Я\"А"), cipher_error);
    }
    
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        // 3.6 Пустой шифротекст
        CHECK_THROW(p->decrypt(L""), cipher_error);
    }
    
    TEST(MaxShiftKey) {
        // 3.7 Максимальный сдвиг
        modAlphaCipher cipher(L"Я");
        string expected = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ";
        string actual = wstring_to_string(cipher.decrypt(L"ЯАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮ"));
        CHECK_EQUAL(expected, actual);
    }
}

// ==================== ГЛАВНАЯ ФУНКЦИЯ ====================

int main()
{
    std::wcout.imbue(std::locale("ru_RU.UTF-8"));
    std::wcerr.imbue(std::locale("ru_RU.UTF-8"));
    
    std::wcout << L"==================================================" << std::endl;
    std::wcout << L"МОДУЛЬНОЕ ТЕСТИРОВАНИЕ ШИФРА ГРОНСФЕЛЬДА" << std::endl;
    std::wcout << L"==================================================" << std::endl << std::endl;
    
    std::wcout << L"Выполняются тесты:" << std::endl;
    std::wcout << L"1. KeyTest - 8 тестов" << std::endl;
    std::wcout << L"2. EncryptTest - 7 тестов" << std::endl;
    std::wcout << L"3. DecryptTest - 7 тестов" << std::endl;
    std::wcout << L"Всего: 22 теста" << std::endl << std::endl;
    
    int result = UnitTest::RunAllTests();
    
    std::wcout << std::endl << L"==================================================" << std::endl;
    std::wcout << L"ТЕСТИРОВАНИЕ ЗАВЕРШЕНО" << std::endl;
    std::wcout << L"==================================================" << std::endl;
    
    return result;
}
