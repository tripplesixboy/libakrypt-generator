# Libakrypt: аннотация

Библиотека `libakrypt` написана на языке Си и реализует механизмы генерации, хранения, экспорта и импорта
ключевой информации, а также основные отечественные криптографические преобразования, регламентированные 
национальными стандартами и рекомендациями по стандартизации.

Цель разработки библиотеки заключается в создании программного модуля с
открытыми исходными текстами для СКЗИ, удовлетворяющего рекомендациям по стандартизации Р 1323565.1.012-2017
«[Принципы разработки и модернизации шифровальных (криптографических) средств защиты
информации](https://tc26.ru/standarts/rekomendatsii-po-standartizatsii/r-1323565-1-012-2017-informatsionnaya-tekhnologiya-kriptograficheskaya-zashchita-informatsii-printsipy-razrabotki-i-modernizatsii-shifrovalnykh-kriptograficheskikh-sredstv-zashchity-informatsii.html)» 
по классу КС3.

Библиотека распространяется по лицензии [MIT](https://git.miem.hse.ru/axelkenzo/libakrypt-0.x/-/raw/master/LICENSE) 
и содержит реализацию следующих криптографических преобразований.


  1. Алгоритмы блочного шифрования "Магма" и "Кузнечик", регламентированные в ГОСТ Р 34.13-1015,
     см. также [RFC 8891](https://tools.ietf.org/html/rfc8891) and [RFC 7801](https://tools.ietf.org/html/rfc7801);
  2. Режимы блочного шифрования ГОСТ Р 34.13-2015, включая режим выработки имитовставки;
  3. Режим шифрования ACPKM, см. рекомендации Р 1323565.1.017-2018 
     и [RFC 8645](https://tools.ietf.org/html/rfc8645);
  4. Режим шифрования XTS, см. [IEEE 1619-2007](https://standards.ieee.org/standard/1619-2007.html);
  5. Режимы аутентификационного шифрования, включая режим MGM (Multilinear Galois mode), 
     рекомендуемый в Р 1323565.026-2019, см. также [RFC 9058](https://tools.ietf.org/html/rfc9058);
  6. Функции хеширования семейства "Стрибог", стандартизированные в ГОСТ Р 34.11-2012, 
     см. также [RFC 6986](https://tools.ietf.org/html/rfc6986);
  7. Криптографические алгоритмы из рекомендаций Р 50.1.113-2016, включая алгоритм HMAC;
  8. Функция выработки ключа из пароля (PBKDF2), рекомендованная в Р 50.1.111-2016;
  9. Несколько генераторов псевдослучайных чисел, включая алгоритм рекомендованный в Р 1323565.1.006-2017;
 10. Арифметика Монтгомери для конечных простых полей;
 11. Операции в группе точек эллиптической кривой в формах Вейерштрасса и Эдвардса.
     Поддерживаются все эллиптические кривые, указанные в рекомендациях Р 1323565.024-2019;
 12. Процедуры выработки и проверки электронной подписи согласно ГОСТР Р 34.10-2012 и ISO/IEC 14888-3:2016;
 13. Низкоуровневые функции для работы с ASN.1 нотацией и кодирования данных в форматах DER и PEM, 
     см. ГОСТ Р ИСО/МЭК 8825-1-2003;
 14. Функции для работы с сертфикатами форматов x509, включая форматы открытых ключей, описываемые 
     в рекомендациях Р 1323565.023-2018 и [RFC 5652](https://tools.ietf.org/html/rfc5652);
 15. Схема Блома для выработки симметричных ключей парной связи.


Библиотека `libakrypt` может быть собрана различными компиляторами такими, как `gcc`, `clang`, 
`Microsoft Visual C`, `TinyCC` и `icc`. Система сборки: [cmake](https://cmake.org/).

Поддерживаемая архитектура: `x86`, `x64`, `arm32v7`, `arm32v7eb`, `armhf`, `mips32r2` и `mips64r2`.

Библиотека может применяться в различных операционных системах: `Linux`, `Windows` и `FreeBSD`.
Также были успешные тестовые запуски библиотеки под 
[ReactOS](https://reactos.org), [Sailfish OS](https://sailfishos.org/) и
[PetaLinux](https://www.xilinx.com/products/design-tools/embedded-software/petalinux-sdk.html).

# Libakrypt: сборка

Получить исходные коды библиотеки можно с помощью следующего вызова.

    git clone https://git.miem.hse.ru/axelkenzo/libakrypt-0.x

Cборка библиотеки осуществляется привычным способом.

    mkdir build
    cd build
    cmake ../libakrypt-0.x
    make

После компиляции исходных текстов будут собраны две библиотеки `libakrypt-base` и `libakrypt`,
а также консольная утилита `aktool`.
Установка собранных библиотек и консольной утилиты выполняется с правами суперпользователя следующим образом.

    make install

# Libakrypt: документация

Документация, а также подробная инструкция по установке и сборке 
библиотеки, находится по адресу: [http://libakrypt.ru](http://libakrypt.ru),
а также может быть найдена в подкаталоге `doc` дерева исходных текстов библиотеки.


