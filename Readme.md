# Libakrypt: аннотация

Библиотека `libakrypt` написана на языке Си и реализует механизмы генерации, 
хранения, экспорта и импорта ключевой информации, а также основные 
отечественные криптографические преобразования, регламентированные 
национальными стандартами и рекомендациями по стандартизации.

Цель разработки библиотеки заключается в создании программного модуля с
открытыми исходными текстами для СКЗИ, удовлетворяющего рекомендациям 
по стандартизации Р 1323565.1.012-2017
«[Принципы разработки и модернизации шифровальных (криптографических) средств защиты
информации](https://tc26.ru/standarts/rekomendatsii-po-standartizatsii/r-1323565-1-012-2017-informatsionnaya-tekhnologiya-kriptograficheskaya-zashchita-informatsii-printsipy-razrabotki-i-modernizatsii-shifrovalnykh-kriptograficheskikh-sredstv-zashchity-informatsii.html)» 
по классу КС3.

Библиотека может применяться в различных операционных системах: `Linux`, 
`Windows` и `FreeBSD`. Также были успешные тестовые запуски библиотеки под 
управлением [ReactOS](https://reactos.org), 
[Sailfish OS](https://sailfishos.org/) и
[PetaLinux](https://www.xilinx.com/products/design-tools/embedded-software/petalinux-sdk.html).

# Libakrypt: сборка

Библиотека `libakrypt` может быть собрана различными компиляторами такими, 
как `gcc`, `clang`, `Microsoft Visual C`, `TinyCC` и `icc`. 
Система сборки: [cmake](https://cmake.org/).

Поддерживаемая архитектура: `x86`, `x64`, `arm32v7`, 
`arm32v7eb`, `armhf`, `mips32r2` и `mips64r2`.

Получить исходные коды библиотеки можно с помощью следующего вызова.

    git clone https://git.miem.hse.ru/axelkenzo/libakrypt-0.x

Cборка библиотеки осуществляется привычным способом.

    mkdir build
    cd build
    cmake ../libakrypt-0.x
    make

После компиляции исходных текстов будут собраны две 
библиотеки `libakrypt-base` и `libakrypt`, а также консольная утилита `aktool`.
Установка собранных библиотек и консольной утилиты выполняется с правами 
суперпользователя следующим образом.

    make install

# Libakrypt: документация

Документация, а также подробная инструкция по установке и сборке 
библиотеки, находится по адресу: [libakrypt.ru](https://libakrypt.ru),
а также может быть найдена в подкаталоге `doc` дерева исходных текстов библиотеки.

# Libakrypt: лицензия

Библиотека распространяется по лицензии 
[MIT](https://git.miem.hse.ru/axelkenzo/libakrypt-0.x/-/raw/master/LICENSE).





