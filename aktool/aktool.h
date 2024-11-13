/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2021, 2024 by Axel Kenzo, axelkenzo@mail.ru                               */
/*                                                                                                 */
/*  Файл aktool.h                                                                                  */
/*  - содержит объявления служебных функций консольного клиента                                    */
/* ----------------------------------------------------------------------------------------------- */
 #ifndef AKTOOL_H
 #define AKTOOL_H

/* ----------------------------------------------------------------------------------------------- */
 #include <getopt.h>
 #include <libakrypt.h>

/* ----------------------------------------------------------------------------------------------- */
#ifdef AK_HAVE_LOCALE_H
 #include <locale.h>
#endif
#ifdef AK_HAVE_LIBINTL_H
 #include <libintl.h>
 #define _( string ) gettext( string )
#else
 #define _( string ) ( string )
#endif
#ifdef AK_HAVE_TIME_H
 #include <time.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
 #define aktool_password_max_length (256)

/* ----------------------------------------------------------------------------------------------- */
#if defined(__unix__) || defined(__APPLE__)
  #define aktool_default_generator "dev-random"
#else
  #ifdef AK_HAVE_WINDOWS_H
    #define aktool_default_generator "winrtl"
  #else
    #define aktool_default_generator "lcg"
  #endif
#endif

/* ----------------------------------------------------------------------------------------------- */
 typedef int ( ak_function_icode_ptr ) ( ak_pointer , const ak_pointer ,
                                                       const size_t , ak_pointer , const size_t );
 typedef int ( ak_function_icode_file ) ( ak_pointer , const char * , ak_pointer , const size_t );
 typedef int ( ak_function_icode_file_offset ) ( ak_pointer , const char * ,
                                                ak_int64 , ak_int64 , ak_pointer , const size_t );

/* ----------------------------------------------------------------------------------------------- */
 typedef struct {
  /*! \brief Начальный адрес области памяти */
   size_t st_addr;
  /*! \brief Конечный адрес области памяти */
   size_t en_addr;
  /*! \brief Смещение фрагмента памяти от начала файла */
    size_t offset;
 } memaddr_t;

/* ----------------------------------------------------------------------------------------------- */
/* структура с глобальными опциями программы */
 typedef struct {
  /* уровень аудита */
   int aktool_log_level;
  /* флаг совместимости с форматами библиотеки openssl */
   bool_t aktool_openssl_compability;
  /* флаг ввода пароля в шестнадцатеричной системе счисления */
   bool_t aktool_hex_password_input;
  /* расширенный вывод сообщений */
   bool_t verbose;
  /* запрашивать подтверждение при удалении файлов */
   bool_t confirm;
  /* режим тишины (ни чего не выводим, используем код возврата) */
   bool_t quiet;
  /* показывать ли заголовки в выводимых таблицах */
   int show_caption;
  /* идентификатор используемого (криптографического) метода */
   ak_oid method;
  /* идентификатор режима применения криптографического метода */
   ak_oid mode;
  /* контекст алгоритма хеширования/мастер ключа */
   ak_pointer handle;
#ifdef AK_HAVE_GELF_H
  /* указатель на функцию криптографического сжатия информации */
   ak_function_icode_ptr *icode_ptr;
  /* указатель на функцию очистки контекста */
  ak_function_clean *icode_clean;
  /* указатель на функцию обработки одного блока */
  ak_function_update *icode_update;
  /* указатель на функцию завершения обработки */
  ak_function_finalize *icode_finalize;
#endif
  /* указатель на функцию криптографического сжатия информации */
   ak_function_icode_file *icode_file;
  /* указатель на функцию криптографического сжатия фрагмента информации */
   ak_function_icode_file_offset *icode_file_offset;
  /* идентификатор алгоритма генерации случайных значений */
   ak_oid oid_of_generator;
  /* имя файла со случайными последовательностями (как правило, специальное блочное устройство) */
   char *name_of_file_for_generator;
  /* указатель на генератор */
   ak_random generator;
  /* идентификатор цели выполнения программы */
   ak_oid oid_of_target;
  /* формат цели выполнения программы */
   export_format_t format;
  /* использование неопределеного типа цели */
   bool_t target_undefined;
  /* идентификатор эллиптической кривой */
   ak_oid curve;
  /* срок действия (в сутках) */
   size_t days;
  /* размер конечного поля характеристики два */
   ak_uint32 field;
  /* количество элементов поля */
   ak_uint32 size;
  /* метка ключа */
   char *keylabel;
  /* длина имени пользователя */
   ssize_t lenuser;
  /* длина пароля для входного файла */
   ssize_t leninpass;
  /* длина пароля для выходного файла */
   ssize_t lenoutpass;
  /* идентификатор пользователя (владельца) ключа  */
   char userid[256];
  /* пароль для входного файла */
   char inpass[aktool_password_max_length];
  /* пароль для создаваемого файла */
   char outpass[aktool_password_max_length];
  /* не использовать пароль для выходного файла */
   bool_t no_outpass;
  /* длина пароля для ввода дополнительного секретного ключа */
   ssize_t lenckpass;
  /* пароль для ввода дополнительного пароля доступа к ключу */
   char ckpass[aktool_password_max_length];
  /* длина пароля для доступа к секретному асимметричному ключу */
   ssize_t lenkeypass;
  /* пароль для доступа к секретному асимметричному ключу */
   char keypass[aktool_password_max_length];

  /* имя файла аудита */
   char audit_filename[512];
   char os_file[1024]; /* сохраняем, секретный ключ */
   char op_file[1024];  /* сохраняем, открытый ключ */
   char key_file[1024];   /* читаем, секретный ключ */
   char pubkey_file[1024]; /* читаем, открытый ключ */
   char capubkey_file[1024]; /* читаем второй (дополнительный) открытый ключ */
  /* открытый ключ */
   struct certificate cert;
  /* шаблон для поиска файлов */
   char *pattern;
  /* счетчик числа ошибочных вызовов */
   struct icode_stat {
     /* общее количество найденных файлов */
      size_t total_files;
     /* количество обработанных файлов */
      size_t hashed_files;
     /* количество необработанных файлов */
      size_t skiped_files;
 #ifdef AK_HAVE_GELF_H
     /* количество исполняемых файлов */
      size_t executables;
     /* количество отброшенных исполняемых файлов */
      size_t skipped_executables;
     /* количество отброшенных ссылок */
      size_t skipped_links;
     /* полное количество процессов тестируемых провессов */
      size_t processes;
     /* количество отброшенных процессов */
      size_t skipped_processes;
     /* количество сегментов */
      size_t segments;
     /* количество неверных сегментов */
      size_t skipped_segments;
 #endif
     /* общее количество строк в обрабатываемом файле */
      size_t total_lines;
     /* общее количество непрочитанных строк */
      size_t skiped_lines;
     /* количество удаленных файлов */
      size_t deleted_files;
     /* количество измененных файлов */
      size_t changed_files;
     /* количество новых файлов */
      size_t new_files;
   } statistical_data;
  /* при установленном флаге программа не проверяет сегменты, загружаемые в память */
   bool_t ignore_segments;
  /* при установленном флаге программа проверяет только сегменты, загружаемые в память
     все остальное пропускается */
   bool_t only_segments;
  /* список каталогов для проверки */
   struct list include_path;
  /* список файлов для проверки */
   struct list include_file;
  /* список исключений среди файлов */
   struct htable exclude_file;
#ifdef AK_HAVE_GELF_H
  /* список исключений среди ссылок в памяти процесса на файлы */
   struct htable exclude_link;
  /* временный список, содержащий длины необработанных фрагментов фалов, загруженных в память */
   struct htable fragments_lens;
#endif
  /* список исключений среди каталогов */
   struct htable exclude_path;
  /* флаг рекурсивной обработки каталогов */
   bool_t tree;
  /* вывод результата в стиле BSD */
   bool_t tag;
  /* флаг разворота выводимых/вводимых результатов */
   bool_t reverse_order;
  /* флаг поиска удаленных файлов */
   bool_t search_deleted;
  /* флаг использования производных ключей */
   bool_t key_derive;
  /* таблица со значениями контрольных сумм */
   struct htable icodes;
  /* количество узлов первого уровня в хэш-таблице */
   size_t icode_lists_count;
  /* при установленном флаге программа не прерывается */
   bool_t ignore_errors;
  /* при установленном флаге программа не выводит в консоль значения вычисоенных контрольных сумм */
   bool_t dont_show_icode;
  /* при установленном флаге программа не выводит статистику */
   bool_t dont_show_stat;
  /* при установленном флаге программа не сохраняет вычисленные коды в базу данных */
   bool_t dont_save_database;
  /* размер смещения о начала файла */
   ak_int64 offset;
  /* размер обрабатываемого фрагмента */
   ak_int64 data_size;
#ifdef AK_HAVE_GELF_H
  /* текущий процесс для проверки целостности */
   pid_t pid;
  /* минимальный номер процесса для проверки целостности */
   pid_t min_pid;
  /* максимальный номер процесса для проверки целостности */
   pid_t max_pid;
  /* текущий фрагмент карты памяти */
   memaddr_t curmem;
#endif
 #ifdef AK_HAVE_BZLIB_H
  /* сжимать файлы, перед обработкой */
   bool_t compress_bz2;
 #endif
  /* уничтожать исходные данные после их криптографической обработки */
   bool_t delete_source;
} aktool_ki_t;

/* собственно глобальная переменная с опциями */
 extern aktool_ki_t ki;

/* ----------------------------------------------------------------------------------------------- */
/* вывод очень короткой справки о программе */
 int aktool_litehelp( void );
/* вывод версии */
 int aktool_version( void );
/* вывод длинной справки о программе */
 int aktool_help( void );
/* вывод информации об ощих опциях */
 int aktool_print_common_options( void );
/* вывод произвольного сообщения через gettext() */
 int aktool_print_gettext( const char * );
/* проверка корректности заданной пользователем команды */
 bool_t aktool_check_command( const char *, tchar * );
/* вывод сообщений в заданный пользователем файл, а также в стандартный демон вывода сообщений */
 int aktool_audit_function( const char * );
/* определение функции вывода сообщений о ходе выполнения программы */
 void aktool_set_audit( tchar * );
/* вывод в консоль строки с сообщением об ошибке */
 void aktool_error( const char *format, ... );
/* общий для всех подпрограмм запуск процедуры инициализации билиотеки */
 bool_t aktool_create_libakrypt( void );
/* общий для всех подпрограмм запуск процедуры остановки билиотеки */
 int aktool_destroy_libakrypt( void );
/* функция создает новый генератор псевдослучайных чисел */
 ak_random aktool_key_new_generator( void );
/* функция удаляет генератор псевдослучайных чисел */
 void aktool_key_delete_generator( ak_random );
/* функция удаляет заданный файл */
 int aktool_remove_file( const tchar * );

/* функция однократного чтения ключа */
 ssize_t aktool_load_user_password( const char *, char *, const size_t , password_t );
/* функция двукратного чтения ключа */
 ssize_t aktool_load_user_password_twice( char * , const size_t );

/* ----------------------------------------------------------------------------------------------- */
/* реализации пользовательских команд */
 int aktool_show( int argc, tchar *argv[] );
 int aktool_test( int argc, tchar *argv[] );
 int aktool_asn1( int argc, tchar *argv[] );
 int aktool_key( int argc, tchar *argv[] );

/* ----------------------------------------------------------------------------------------------- */
/*! формат сохранения файла с вычисленными значениями */
 typedef enum
{
   format_binary = 0x00,
   format_linux = 0x01,
   format_bsd = 0x02
}
 aktool_icode_format_t;

/* ----------------------------------------------------------------------------------------------- */
/* глобальный вызов команды контроля целостности */
 int aktool_icode( int argc, tchar *argv[] );
/* добавление объекта для контроля целостности (каталога или файла) */
 int aktool_icode_add_control_object( aktool_ki_t * , const char * , const char * );
/* чтение конфигурационного файла для команды icode */
 int aktool_icode_read_config( char *, aktool_ki_t * );
/* функция вычисляет контроьные суммы */
 int aktool_icode_evaluate( aktool_ki_t * );
/* функция создает криптографический контекст, реализующий вычисление контрольной суммы */
 int aktool_icode_create_handle( aktool_ki_t * );
/* функция уничтожает криптографический контекст */
 int aktool_icode_destroy_handle( aktool_ki_t * );
/* функция для выработки производного ключа контроля целостности */
 ak_pointer aktool_icode_get_derived_key( const char * , aktool_ki_t * , ak_uint64 );
/* вывод контрольной суммы в консоль */
 void aktool_icode_out( FILE * , const char * , aktool_ki_t * , ak_uint8 * , const size_t );
/* вывод всех контрольных сумм в консоль */
 int aktool_icode_out_all( FILE * , aktool_ki_t * );
/* сохранение файла с вычисленными контрольными суммами */
 int aktool_icode_export_checksum( aktool_ki_t * );
/* чтение файла с вычисленными ранее контрольными суммами */
 int aktool_icode_import_checksum( aktool_ki_t * );
/* проверка контрольных сумм по заданой базе данных */
 int aktool_icode_check_from_database( aktool_ki_t * );
/* проверка контрольных сумм для заданных каталогов и файлов */
 int aktool_icode_check_from_directory( aktool_ki_t * );
#ifdef AK_HAVE_GELF_H
/* проверка контрольных сумм для процессов в оперативной памяти */
 int aktool_icode_check_processes( aktool_ki_t * );
#endif
/* чтение файла с конфигурацией */
 int aktool_icode_read_config( char * , aktool_ki_t * );

/* ----------------------------------------------------------------------------------------------- */
 typedef enum { do_nothing, do_encrypt, do_decrypt } encrypt_t;
 int aktool_encrypt( int argc, tchar *argv[], encrypt_t work );

/* ----------------------------------------------------------------------------------------------- */
/* это стандартные для всех программ опции */
 #define aktool_common_letters_definition "h"
 #define aktool_common_functions_definition { "help",                0, NULL,  'h' },\
                                            { "audit-file",          1, NULL,   2  },\
                                            { "dont-use-colors",     0, NULL,   3  },\
                                            { "audit",               1, NULL,   4  },\
                                            { "openssl-style",       0, NULL,   5  },\
                                            { "hex-input",           0, NULL,   6  },\
                                            { "verbose",             0, NULL,   7  },\
                                            { "quiet",               0, NULL,   8  },\
                                            { "confirm",             0, NULL,   9  }

 #define aktool_common_functions_run( help_function )   \
     case 'h' :   return help_function();\
     case  2  : /* получили от пользователя имя файла для вывода аудита */\
        aktool_set_audit( optarg );\
        break;\
     case  3  : /* установка флага запрета вывода символов смены цветовой палитры */\
        ak_error_set_color_output( ak_false );\
        ak_libakrypt_set_option( "use_color_output", 0 );\
        break;\
     case  4  : /* устанавливаем уровень аудита */\
        ki.aktool_log_level = atoi( optarg );\
        break;\
     case  5  : /* переходим к стилю openssl */\
        ki.aktool_openssl_compability = ak_true;\
        break;\
     case  6  : /* обрабатываем --hex-input */\
        ki.aktool_hex_password_input = ak_true;\
        break;\
     case  7  : /* обрабатываем --verbose */\
        ki.verbose = ak_true;\
        ki.quiet = ak_false;\
        break;\
     case  8  : /* обрабатываем --quiet */\
        ki.quiet = ak_true;\
        ki.verbose = ak_false;\
        break;\
     case  9  : /* обрабатываем --confirm */\
        ki.confirm = ak_true;\
        break;\

 #endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       aktool.h  */
/* ----------------------------------------------------------------------------------------------- */
