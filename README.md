# Реализация алгоритма AES-128 на Python

## Принцип работы алгоритма AES-128

### Общая информация

AES (Advanced Encryption Standard) - симметричный блочный шифр, принятый в качестве стандарта шифрования правительством США. AES-128 использует ключ длиной 128 бит и оперирует блоками данных размером 128 бит (16 байт).

### Основные характеристики

- **Тип шифра**: Симметричный блочный шифр
- **Размер блока**: 128 бит (16 байт)
- **Длина ключа**: 128 бит (16 байт)
- **Количество раундов**: 10 раундов
- **Структура**: Сеть замещения-перестановки (Substitution-Permutation Network)

### Математическая основа

AES работает с данными, представленными в виде двумерного массива байтов размером 4×4, называемого **состоянием** (State). Операции выполняются в конечном поле GF(2^8), где элементы представляют собой многочлены над GF(2) степени не выше 7.

### Этапы шифрования

1. **Начальное добавление ключа (AddRoundKey)** - состояние комбинируется с начальным ключом раунда с помощью операции XOR.

2. **Основные раунды (9 раундов)** - каждый раунд включает 4 преобразования:
   - **SubBytes** - нелинейная замена байтов с использованием таблицы замен (S-box)
   - **ShiftRows** - циклический сдвиг строк состояния влево
   - **MixColumns** - смешивание данных в каждом столбце
   - **AddRoundKey** - добавление ключа раунда с помощью XOR

3. **Финальный раунд (10-й)** - включает 3 преобразования:
   - **SubBytes**
   - **ShiftRows**
   - **AddRoundKey**

### Подробное описание преобразований

#### 1. SubBytes (Замена байтов)

Каждый байт состояния заменяется соответствующим элементом из таблицы замен (S-box). Эта операция обеспечивает нелинейность алгоритма и противостоит линейному и дифференциальному криптоанализу.

S-box является фиксированной таблицей 16×16, полученной путем вычисления мультипликативной инверсии каждого байта в GF(2^8) и последующего применения аффинного преобразования.

#### 2. ShiftRows (Сдвиг строк)

В этом преобразовании строки состояния циклически сдвигаются влево на разное количество позиций:
- Первая строка не сдвигается
- Вторая строка сдвигается на 1 байт влево
- Третья строка сдвигается на 2 байта влево
- Четвертая строка сдвигается на 3 байта влево

Данное преобразование обеспечивает диффузию и влияет на зависимость выходных битов от входных.

#### 3. MixColumns (Смешивание столбцов)

Каждый столбец состояния умножается на фиксированную матрицу:

```
┌ 2 3 1 1 ┐
│ 1 2 3 1 │
│ 1 1 2 3 │
└ 3 1 1 2 ┘
```

Умножение производится в GF(2^8) с использованием неприводимого многочлена x^8 + x^4 + x^3 + x + 1. Это преобразование обеспечивает диффузию между байтами каждого столбца.

#### 4. AddRoundKey (Добавление ключа раунда)

Каждый байт состояния комбинируется с соответствующим байтом ключа раунда с помощью операции XOR.

### Расширение ключа (Key Schedule)

Из исходного ключа длиной 128 бит генерируются 11 ключей раундов (включая начальный) по 128 бит каждый. Расширение ключа включает:
- Использование S-box для нелинейных преобразований
- Применение XOR с константами раунда (RCON)
- Рекурсивные операции для генерации новых слов ключа

### Расшифрование

Процесс расшифрования выполняет все операции шифрования в обратном порядке, используя обратные преобразования:
- **InvSubBytes** - обратная таблица замен
- **InvShiftRows** - сдвиг строк вправо
- **InvMixColumns** - умножение на обратную матрицу
- **AddRoundKey** - остается без изменений (XOR)

### Безопасность

AES-128 обеспечивает надежную защиту и устойчивость к известным методам криптоанализа. На сегодняшний день не существует практически реализуемых атак на полноценную реализацию AES-128.
