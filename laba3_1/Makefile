# Настройки компилятора
CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra -pedantic
LDFLAGS = -lUnitTest++

# Имена файлов
TARGET = test_route
SOURCES = main.cpp routeCipher.cpp
OBJECTS = $(SOURCES:.cpp=.o)
HEADERS = routeCipher.h

UNIT_TEST_INC = /usr/include/UnitTest++
UNIT_TEST_LIB = /usr/lib/x86_64-linux-gnu

# Цели сборки

.PHONY: all clean test debug run help

# Основная цель
all: $(TARGET)

# Сборка исполняемого файла
$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJECTS) -L$(UNIT_TEST_LIB) $(LDFLAGS)

# Компиляция исходных файлов
main.o: main.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) -I$(UNIT_TEST_INC) -c main.cpp -o main.o

routeCipher.o: routeCipher.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) -c routeCipher.cpp -o routeCipher.o

# ========================================================
# Утилиты
# ========================================================

# Запуск тестов
test: $(TARGET)
	@echo "=================================================="
	@echo "ЗАПУСК ТЕСТОВ МАРШРУТНОЙ ПЕРЕСТАНОВКИ"
	@echo "=================================================="
	@./$(TARGET)

# Сборка с отладочной информацией
debug: CXXFLAGS += -g -DDEBUG
debug: clean $(TARGET)

# Быстрый запуск (сборка + тесты)
run: clean test

# Очистка
clean:
	rm -f $(OBJECTS) $(TARGET) *.gcov *.gcno *.gcda

# Справка
help:
	@echo "Доступные команды:"
	@echo "  make all     - сборка проекта (по умолчанию)"
	@echo "  make test    - сборка и запуск тестов"
	@echo "  make run     - очистка, сборка и запуск тестов"
	@echo "  make debug   - сборка с отладочной информацией"
	@echo "  make clean   - удаление скомпилированных файлов"
	@echo "  make help    - эта справка"

# ========================================================
# Информация о системе
# ========================================================
info:
	@echo "Информация о системе:"
	@echo "  Компилятор: $(CXX)"
	@echo "  Флаги компиляции: $(CXXFLAGS)"
	@echo "  Флаги линковки: $(LDFLAGS)"
	@echo "  Исполняемый файл: $(TARGET)"
	@echo "  Исходные файлы: $(SOURCES)"
	@echo "  Заголовочные файлы: $(HEADERS)"
	@echo "  Путь к UnitTest++: $(UNIT_TEST_INC)"
	@echo "  Путь к библиотекам: $(UNIT_TEST_LIB)"
