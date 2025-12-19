#include <UnitTest++/UnitTest++.h>
#include "routeCipher.h"
#include <locale>
#include <algorithm>
#include <string>
#include <iostream>

using namespace std;

// Глобальная настройка локали
struct LocaleSetup {
    LocaleSetup() {
        std::locale::global(std::locale("ru_RU.UTF-8"));
    }
};

LocaleSetup localeSetup;

// ==================== ТЕСТЫ ДЛЯ КОНСТРУКТОРА ====================

SUITE(RouteConstructorTest)
{
    TEST(ValidColumns) {
        routeCipher cipher(5);
        CHECK(true);
    }
    
    TEST(OneColumn) {
        routeCipher cipher(1);
        CHECK(true);
    }
    
    TEST(ZeroColumns) {
        CHECK_THROW(routeCipher cipher(0), route_cipher_error);
    }
    
    TEST(NegativeColumns) {
        CHECK_THROW(routeCipher cipher(-3), route_cipher_error);
    }
    
    TEST(TooManyColumns) {
        CHECK_THROW(routeCipher cipher(1000), route_cipher_error);
    }
    
    TEST(ColumnsMoreThanLetters) {
        routeCipher cipher(50);
        CHECK(true);
    }
}

// ==================== ТЕСТЫ ДЛЯ МЕТОДА ENCRYPT ====================

struct RouteFixture4 {
    routeCipher* p;
    
    RouteFixture4() {
        p = new routeCipher(4);
    }
    
    ~RouteFixture4() {
        delete p;
    }
};

SUITE(RouteEncryptTest)
{
    TEST_FIXTURE(RouteFixture4, UpCaseString) {
        CHECK(p->encrypt(L"АБВГДЕЁЖ") == L"ГЖВЁБЕАД");
    }
    
    TEST_FIXTURE(RouteFixture4, LowCaseString) {
        CHECK(p->encrypt(L"абвгдеёж") == L"ГЖВЁБЕАД");
    }
    
    TEST_FIXTURE(RouteFixture4, StringWithSpaces) {
        CHECK(p->encrypt(L"А Б В Г Д Е Ё Ж") == L"ГЖВЁБЕАД");
    }
    
    TEST_FIXTURE(RouteFixture4, StringWithPunctuation) {
        CHECK(p->encrypt(L"А,Б.В!Г?Д,Е.Ё!Ж") == L"ГЖВЁБЕАД");
    }
    
    TEST_FIXTURE(RouteFixture4, EmptyString) {
        CHECK_THROW(p->encrypt(L""), route_cipher_error);
    }
    
    TEST_FIXTURE(RouteFixture4, NoAlphaString) {
        CHECK_THROW(p->encrypt(L"1234+8765=9999"), route_cipher_error);
    }
    
    TEST_FIXTURE(RouteFixture4, SingleLetter) {
        CHECK(p->encrypt(L"А") == L"А");
    }
    
    TEST_FIXTURE(RouteFixture4, TextNotMultipleOfColumns) {
        // ПРАВИЛЬНЫЙ результат: ГВЁБЕАД
        CHECK(p->encrypt(L"АБВГДЕЁ") == L"ГВЁБЕАД");
    }
    
    TEST(SpecificTestCase1) {
        routeCipher cipher(3);
        CHECK(cipher.encrypt(L"АБВГДЕ") == L"ВЕБДАГ");
    }
    
    TEST(SpecificTestCase2) {
        routeCipher cipher(3);
        // ПРАВИЛЬНЫЙ результат: ВБДАГ
        CHECK(cipher.encrypt(L"АБВГД") == L"ВБДАГ");
    }
    
    TEST(OneColumnEncryption) {
        routeCipher cipher(1);
        CHECK(cipher.encrypt(L"АБВГД") == L"АБВГД");
    }
}

// ==================== ТЕСТЫ ДЛЯ МЕТОДА DECRYPT ====================

SUITE(RouteDecryptTest)
{
    TEST_FIXTURE(RouteFixture4, ValidCipherText) {
        CHECK(p->decrypt(L"ГЖВЁБЕАД") == L"АБВГДЕЁЖ");
    }
    
    TEST_FIXTURE(RouteFixture4, LowCaseCipherText) {
        CHECK_THROW(p->decrypt(L"гЖВЁБЕАД"), route_cipher_error);
    }
    
    TEST_FIXTURE(RouteFixture4, WhitespaceCipherText) {
        CHECK_THROW(p->decrypt(L"ГЖ ВЁБ ЕАД"), route_cipher_error);
    }
    
    TEST_FIXTURE(RouteFixture4, DigitsCipherText) {
        CHECK_THROW(p->decrypt(L"ГЖ123ВЁБЕАД"), route_cipher_error);
    }
    
    TEST_FIXTURE(RouteFixture4, PunctCipherText) {
        CHECK_THROW(p->decrypt(L"Г,Ж.В!Ё?Б-Е:А;Д"), route_cipher_error);
    }
    
    TEST_FIXTURE(RouteFixture4, EmptyCipherText) {
        CHECK_THROW(p->decrypt(L""), route_cipher_error);
    }
    
    TEST(OneColumnDecryption) {
        routeCipher cipher(1);
        CHECK(cipher.decrypt(L"АБВГД") == L"АБВГД");
    }
    
    TEST_FIXTURE(RouteFixture4, RoundTrip) {
        wstring original = L"ПРОГРАММИРОВАНИЕЭТОИНТЕРЕСНО";
        wstring encrypted = p->encrypt(original);
        wstring decrypted = p->decrypt(encrypted);
        
        wstring clean_original;
        for (wchar_t c : original) {
            if (c != L' ') {
                clean_original += towupper(c);
            }
        }
        
        CHECK(clean_original == decrypted);
    }
    
    TEST(SpecificDecryptTestCase1) {
        routeCipher cipher(3);
        CHECK(cipher.decrypt(L"ВЕБДАГ") == L"АБВГДЕ");
    }
    
    TEST(SpecificDecryptTestCase2) {
        routeCipher cipher(3);
        wstring original = L"АБВГД";
        wstring encrypted = cipher.encrypt(original);
        wstring decrypted = cipher.decrypt(encrypted);
        CHECK(original == decrypted);
    }
}

// ==================== ГЛАВНАЯ ФУНКЦИЯ ====================

int main()
{
    // Настройка локали
    std::locale::global(std::locale("ru_RU.UTF-8"));
    
    wcout << L"==================================================" << endl;
    wcout << L"МОДУЛЬНОЕ ТЕСТИРОВАНИЕ МАРШРУТНОЙ ПЕРЕСТАНОВКИ" << endl;
    wcout << L"==================================================" << endl << endl;
    
    wcout << L"Выполняются тесты:" << endl;
    wcout << L"1. RouteConstructorTest - 6 тестов" << endl;
    wcout << L"2. RouteEncryptTest - 11 тестов" << endl;
    wcout << L"3. RouteDecryptTest - 10 тестов" << endl;
    wcout << L"Всего: 27 тестов" << endl << endl;
    
    // Запуск всех тестов
    int result = UnitTest::RunAllTests();
    
    wcout << endl << L"==================================================" << endl;
    wcout << L"ТЕСТИРОВАНИЕ ЗАВЕРШЕНО" << endl;
    wcout << L"==================================================" << endl;
    
    return result;
}