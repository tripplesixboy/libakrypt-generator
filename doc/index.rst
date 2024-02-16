..
   documentation master file, created by
   sphinx-quickstart on Sun Apr 17 02:37:11 2022.

Проект libakrypt
================

Целью проекта **libakrypt** является разработка и продвижение свободно 
распространяемых программных средств защиты информации, удовлетворяющих 
рекомендациям по стандартизации [P1323565.1.012-2017]_. 
Проект разрабатывается на языке Си и распространяется под лицензией 
`MIT <https://git.miem.hse.ru/axelkenzo/libakrypt-0.x/-/raw/master/LICENSE>`__.

В состав проекта входят:

- библиотека **libakrypt**, реализующая базовые
  преобразования в соответствии с российскими стандартами и рекомендациями
  по стандартизации в области криптографической защиты информации,
- утилита **aktool**, предназначенная для выработки ключевой информации и
  криптографического преобразования информации в пространстве пользователя.

.. note::
  Последняя версия исходных текстов библиотеки **libakrypt** может быть скачана
  с сайта: `https://git.miem.hse.ru/axelkenzo/libakrypt-0.x
  <https://git.miem.hse.ru/axelkenzo/libakrypt-0.x>`__

.. toctree::
   :caption: Пользователям
   :maxdepth: 2
   :hidden:

   10-annotation.rst
   20-install-guide.rst
   30-faq.rst
   90-aktool.rst

.. toctree::
   :maxdepth: 2
   :caption: Разработчикам
   :hidden:

   API функций библиотеки <https://libakrypt.ru/api/topics.html>
   99-bibliography.rst

..
   Архив QCH для QtCreator <https://libakrypt.ru/api/akrypt-library.qch>
