/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2018 - 2021, 2024 by Axel Kenzo, axelkenzo@mail.ru                               */
/*                                                                                                 */
/*  Прикладной модуль, реализующий процедуры проверки целостности данных                           */
/*                                                                                                 */
/*  aktool_icode.c                                                                                 */
/* ----------------------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include "aktool.h"
#ifdef AK_HAVE_ERRNO_H
 #include <errno.h>
#endif
#ifdef AK_HAVE_GELF_H
 #include <gelf.h>
#endif
#ifdef AK_HAVE_UNISTD_H
 #include <unistd.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
 int aktool_icode_help( void );
 void aktool_icode_log_options( aktool_ki_t * );

/* ----------------------------------------------------------------------------------------------- */
 int aktool_icode( int argc, tchar *argv[] )
{
  int next_option = 0, exit_status = EXIT_FAILURE;
  enum { do_nothing, do_hash, do_check } work = do_hash;

  const struct option long_options[] = {
   /* сначала уникальные */
     { "algorithm",           1, NULL,  'a' },
     { "config",              1, NULL,  'c' },
     { "exclude",             1, NULL,  'e' },
     { "pattern",             1, NULL,  'p' },
     { "recursive",           0, NULL,  'r' },
     { "verify",              1, NULL,  'v' },
     { "reverse-order",       0, NULL,  254 },
     { "tag",                 0, NULL,  250 },
     { "hash-table-nodes",    1, NULL,  222 },
     { "output",              1, NULL,  'o' },
     { "no-derive",           0, NULL,  160 },
     { "dont-show-stat",      0, NULL,  161 },
     { "dont-show-icode",     0, NULL,  162 },
     { "format",              1, NULL,  163 },
#ifdef AK_HAVE_GELF_H
     { "with-segments",       0, NULL,  164 },
     { "only-segments",       0, NULL,  165 },
     { "pid",                 1, NULL,  166 },
     { "only-one-pid",        1, NULL,  166 },
#endif

    /* аналоги из aktool_key */
     { "key",                 1, NULL,  203 },
     { "inpass-hex",          1, NULL,  251 },
     { "inpass",              1, NULL,  252 },

   /* это стандартые для всех программ опции */
     aktool_common_functions_definition,
     { NULL,                  0, NULL,   0  },
  };

 /* проверяем доступ к библиотеке libelf (делаем это заранее) */
 #ifdef AK_HAVE_GELF_H
  if( elf_version( EV_CURRENT ) == EV_NONE ) {
    aktool_error(_("ELF library initialization failed: %s"), elf_errmsg(-1));
    return EXIT_FAILURE;
  }
 #endif

 /* заполняем поля структуры с параметрами по-умолчанию */
  memset( &ki, 0, sizeof( aktool_ki_t ));
  ak_htable_create( &ki.exclude_path, 16 );
  ak_htable_create( &ki.exclude_file, 16 );
  ki.pattern =
  #ifdef _WIN32
   strdup("*.*");
  #else
   strdup("*");
  #endif
  ki.tree = ak_false;
  ki.reverse_order = ak_false;
  ki.tag = ak_false;
  ki.icode_lists_count = 1024;
  ki.method = ak_oid_find_by_name( "streebog256" );
  ki.key_derive = ak_true;
  ki.field = format_binary;
  ki.ignore_segments = ak_true;
  ki.only_segments = ak_false;
  ki.dont_show_icode = ak_false;
  ki.pid = -1;

 /* разбираем опции командной строки */
  do {
       next_option = getopt_long( argc, argv, "he:rp:o:a:c:v:", long_options, NULL );
       switch( next_option )
      {
        aktool_common_functions_run( aktool_icode_help );

        case 'a': /* --algorithm  устанавливаем имя криптографического алгоритма */
                   if(( ki.method = ak_oid_find_by_ni( optarg )) == NULL ) {
                     aktool_error(_("using unsupported name or identifier \"%s\""), optarg );
                     printf(
                         _("try \"aktool s --oid hash\" for list of all available identifiers\n"));
                     goto exitlab;
                   }

                   if( ki.method->engine != hash_function ) {
                     aktool_error(
                                 _("option --algorithm accepts only keyless integrity mechanism"));
                     printf(
                         _("try \"aktool s --oid hash\" for list of all available identifiers\n"));
                     goto exitlab;
                   }
                   break;

        case 'c': /* --config устанавливаем имя конфигурационного файла */
                  #ifdef _WIN32
                   GetFullPathName( optarg, FILENAME_MAX, ki.capubkey_file, NULL );
                  #else
                   if( ak_realpath( optarg, ki.capubkey_file,
                                                sizeof( ki.capubkey_file ) -1 ) != ak_error_ok ) {
                     aktool_error(_("the full name of config file cannot be created"));
                     goto exitlab;
                   }
                  #endif
                   break;

        case 222 : /* --hash-table-nodes устанавливаем количество узлов верхнего уровня в хеш-таблице
                      результирующее значение всегда находится между 16 и 4096 */
                   ki.icode_lists_count = ak_min( 4096, ak_max( 16, atoi( optarg )));
                   break;

        case 'o' : /* --output устанавливаем имя файла c результатами вычислений */
                  #ifdef _WIN32
                   GetFullPathName( optarg, FILENAME_MAX, ki.pubkey_file, NULL );
                  #else
                   if( ak_realpath( optarg, ki.pubkey_file,
                                                  sizeof( ki.pubkey_file ) -1 ) != ak_error_ok ) {
                     aktool_error(_("the full name of file with generated "
                                                        "authentication codes cannot be created"));
                     goto exitlab;
                   }
                  #endif
                   break;

        case 'e' : /* --exclude устанавливаем имя исключаемого файла или каталога */
                   aktool_icode_add_control_object( &ki, "exclude", optarg );
                   break;

        case 'p' : /* --pattern устанавливаем дополнительную маску для поиска файлов */
                   if( ki.pattern != NULL ) free( ki.pattern );
                   ki.pattern = strdup( optarg );
                   break;

        case 'r' : /* --recursive устанавливаем флаг рекурсивного обхода каталогов */
                   ki.tree = ak_true;
                   break;

        case 254 : /* --reverse-order установить обратный порядок вывода байт */
                   ki.reverse_order = ak_true;
                   break;

        case 250 : /* --tag вывод в стиле BSD */
                   ki.tag = ak_true;
                   break;

        case 252: /* --inpass */
                   memset( ki.inpass, 0, sizeof( ki.inpass ));
                   strncpy( ki.inpass, optarg, sizeof( ki.inpass ) -1 );
                   if(( ki.leninpass = strlen( ki.inpass )) == 0 ) {
                     aktool_error(_("the password cannot be zero length"));
                     goto exitlab;
                   }
                   break;

        case 251: /* --inpass-hex */
                   ki.leninpass = 0;
                   memset( ki.inpass, 0, sizeof( ki.inpass ));
                   if( ak_hexstr_to_ptr( optarg, ki.inpass,
                                                sizeof( ki.inpass ), ak_false ) == ak_error_ok ) {
                     ki.leninpass = ak_min(( strlen( optarg )%2 ) + ( strlen( optarg ) >> 1 ),
                                                                              sizeof( ki.inpass ));
                   }
                   if( ki.leninpass == 0 ) {
                       aktool_error(_("the password cannot be zero length, "
                                                    "maybe input error, see --inpass-hex %s%s%s"),
                                  ak_error_get_start_string(), optarg, ak_error_get_end_string( ));
                       goto exitlab;
                   }
                   break;

        case 203: /* --key устанавливаем имя файла, содержащего секретный ключ */
                  #ifdef _WIN32
                   GetFullPathName( optarg, FILENAME_MAX, ki.key_file, NULL );
                  #else
                   if( ak_realpath( optarg, ki.key_file,
                                                     sizeof( ki.key_file ) -1 ) != ak_error_ok ) {
                     aktool_error(
                                 _("the full name of key file \"%s\" cannot be created"), optarg );
                     goto exitlab;
                   }
                  #endif
                   break;

        case 'v' : /* --verify выполняем проверку контрольных сумм */
                   work = do_check;
                 #ifdef _WIN32
                   GetFullPathName( optarg, FILENAME_MAX, ki.os_file, NULL );
                 #else
                   if( ak_realpath( optarg, ki.os_file, sizeof( ki.os_file ) -1 ) != ak_error_ok )
                   {
                     aktool_error(
                            _("the full name of checksum file \"%s\" cannot be created"), optarg );
                     goto exitlab;
                   }
                 #endif
                   break;

        case 160: /* --no-derive */
                   ki.key_derive = ak_false;
                   break;

        case 161: /* --dont-show-stat */
                   ki.dont_show_stat = ak_true;
                   break;

        case 162: /* --dont-show-icode */
                   ki.dont_show_icode = ak_true;
                   break;

        case 163: /* --format устанавливаем формат хранения вычисленных/проверочных значений */
                   if( memcmp( optarg, "bsd", 3 ) == 0 ) ki.field = format_bsd;
                   if( memcmp( optarg, "linux", 5 ) == 0 ) ki.field = format_linux;
                   break;

#ifdef AK_HAVE_GELF_H
        case 164: /* --with-segments */
                   ki.ignore_segments = ak_false;
                   break;

        case 165: /* --only-segments */
                   ki.only_segments = ak_true;
                   ki.ignore_segments = ak_false;
                   break;

        case 166: /* --only-one-pid, --pid */
                   if(( ki.pid = atoi( optarg )) < 0 ) {
                     aktool_error(
                      _("incorrect value of the process identifier (pid), option --only-one-pid"));
                     goto exitlab;
                   }
                   ki.ignore_segments = ak_false;
                   break;
#endif

        default:  /* обрабатываем ошибочные параметры */
                   if( next_option != -1 ) goto exitlab;
                   break;
      }

  } while( next_option != -1 );

 /* завершаем обработку параметров без флагов
    все они интерпретируются как файлы или каталоги для контроля целостности */
  ++optind; /* пропускаем команду - i или icode */
 /* начинаем цикл добавления файлов и каталогов, указанных пользователем */
  while( optind < argc ) aktool_icode_add_control_object( &ki, "", argv[optind++] );

 /* начинаем работу с криптографическими примитивами */
  if( !aktool_create_libakrypt( )) goto exitlab;

 // /* считываем оставшиеся конфигурационные настройки из заданного файла */
 //  if( strlen( ki.capubkey_file ) > 0 ) {
 //    if(( exit_status = aktool_icode_read_config( ki.capubkey_file, &ki )) != ak_error_ok )
 //      goto exitlab;
 //  }

 /* разбираемся с именем файла для сохранения результатов */
  if( strlen( ki.pubkey_file ) == 0 ) {
   #ifdef _WIN32
     GetFullPathName( "aktool.icodes", FILENAME_MAX, ki.pubkey_file, NULL );
    #else
     ak_realpath( "/var/tmp/aktool.icodes", ki.pubkey_file, sizeof( ki.pubkey_file ) -1 );
    #endif
  }

 /* выполняем аудит настроек перед запуском программы  */
  aktool_icode_log_options( &ki );

 /* теперь выбираем, что делать */
  switch( work ) {
    case do_hash:
     /* создаем таблицу для хранения контрольных сумм */
       if( ak_htable_create( &ki.icodes, ki.icode_lists_count ) != ak_error_ok ) goto exitlab;
     /* выполняем вычисления */
       if(( exit_status = aktool_icode_evaluate( &ki )) != EXIT_SUCCESS ) goto exitlab;
      /* сохраняем результат */
       exit_status = aktool_icode_export_checksum( &ki );
      break;

    case do_check:
     /* считываем таблицу с сохраненными значениями контрольных сумм */
      if( aktool_icode_import_checksum( &ki ) != ak_error_ok ) goto exitlab;
     /* создаем контекст алгоритма хеширования или имитозащиты */
      if( aktool_icode_create_handle( &ki ) != ak_error_ok ) goto exitlab;
     /* выполняем проверку оперативной памяти */
      if(( ki.only_segments ) || ( !ki.ignore_segments )) {
       if(( exit_status = aktool_icode_check_processes( &ki )) != EXIT_SUCCESS ) {
         aktool_icode_destroy_handle( &ki );
         goto exitlab;
       }
      }
     /* выполняем проверку файловой системы,
        логика проверки заключается в следующем:
        - если указаны файлы или каталоги, тогда происходит поиск файлов
          и проверка их контрольных сумм на соотвествие значениям из базы данных
        - если файлы не определены, то перебираются все файлы из сформированной базы данных */
      if( ! ki.only_segments) {
        if( !( ki.include_file.count + ki.include_path.count ))
          exit_status = aktool_icode_check_from_database( &ki );
         else
          exit_status = aktool_icode_check_from_directory( &ki );
      }
     /* уничтожаем контекст алгоритма хеширования или имитозащиты */
      aktool_icode_destroy_handle( &ki );
      break;

    default:
      break;
  }

 /* завершаем выполнение основного процесса */
  exitlab:
    if( ki.pattern != NULL ) free( ki.pattern );
    ak_list_destroy( &ki.include_path );
    ak_list_destroy( &ki.include_file );
    ak_htable_destroy( &ki.exclude_file );
    ak_htable_destroy( &ki.exclude_path );
    ak_htable_destroy( &ki.icodes );
    aktool_destroy_libakrypt();

 return exit_status;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_icode_add_control_object( aktool_ki_t *ki, const char *name, const char *value )
{
    int permissions = 0;

   /* проверяем права доступа к файлу на этапе чтения конфигурационного файла */
    switch( permissions = ak_file_or_directory( value )) {
      case 0:
      case ak_error_access_file:
        aktool_error(_("access to %s (%s)"), value, strerror( errno ));
        ak_error_message_fmt( ak_error_access_file, __func__, "missing file %s", value );
        return 1;
      default:
        break;
    }

   /* добавляем нечто, что пока нам еще не известно */
    if( strlen( name ) == 0 ) {
      switch( permissions ) {
        case DT_DIR:
          if( ak_list_add_node( &(ki->include_path ),
                                       ak_list_node_new_string( value )) != ak_error_ok ) return 0;
           else return 1;
        case DT_REG:
          if( ak_list_add_node( &(ki->include_file ),
                                       ak_list_node_new_string( value )) != ak_error_ok ) return 0;
           else return 1;
        default:
          return 1;
      }
    }
    if(( memcmp( name, "path", 4 ) == 0 ) && ( permissions == DT_DIR )) {
      if( ak_list_add_node( &(ki->include_path ),
                                       ak_list_node_new_string( value )) != ak_error_ok ) return 0;
        else return 1;
    }
    if(( memcmp( name, "file", 4 ) == 0 ) && ( permissions == DT_REG )) {
      if( ak_list_add_node( &(ki->include_file ),
                                       ak_list_node_new_string( value )) != ak_error_ok ) return 0;
        else return 1;
    }
    if( memcmp( name, "exclude", 7 ) == 0 ) {
      switch( permissions ) {
        case DT_DIR:
          if( ak_htable_add_str_str( &ki->exclude_path, value, "path" ) != ak_error_ok ) return 0;
           else return 1;
        case DT_REG:
          if( ak_htable_add_str_str( &ki->exclude_file, value, "file" ) != ak_error_ok ) return 0;
           else return 1;
        default:
          return 1;
      }
    }

 /* пропускаем строки с невнятным наполнением */
 return 1;
}

/* ----------------------------------------------------------------------------------------------- */
/*                               наполнение системы аудита                                         */
/* ----------------------------------------------------------------------------------------------- */
 void aktool_icode_log_options( aktool_ki_t *ki )
{
  /* выполняем полный аудит только на максимальном уровне */
   if( ak_log_get_level() <= ak_log_standard ) return;

  /* выводим те настройки, что умеем обрабатывать */
  /* каталоги */
   ak_error_message( ak_error_ok, __func__, _("directory list:"));
   if( ki->include_path.count ) {
     ak_list_first( &ki->include_path );
     do{
       ak_error_message_fmt( ak_error_ok, __func__,
                                                 " - %s", (char *)ki->include_path.current->data );
     } while( ak_list_next( &ki->include_path ));
   }
  /* файлы */
   ak_error_message( ak_error_ok, __func__, _("file list:"));
   if( ki->include_file.count ) {
     ak_list_first( &ki->include_file );
     do{
       ak_error_message_fmt( ak_error_ok, __func__,
                                                 " - %s", (char *)ki->include_file.current->data );
     } while( ak_list_next( &ki->include_file ));
   }

  /* список пропускаемых каталогов */
   if( ki->exclude_path.count ) {
     size_t i = 0;
     ak_error_message( ak_error_ok, __func__, _("exclude directory:"));
     for( i = 0; i < ki->exclude_path.count; i++ ) {
       ak_list list = &ki->exclude_path.list[i];
       if( list->count ) {
         ak_list_first( list );
         do{
             ak_keypair kp = (ak_keypair)list->current->data;
             ak_error_message_fmt( ak_error_ok, __func__, " - %s", (char *)kp->data );
         } while( ak_list_next( list ));
       }
     }
   }

  /* список пропускаемых файлов */
   if( ki->exclude_file.count ) {
     size_t i = 0;
     ak_error_message( ak_error_ok, __func__, _("exclude file:"));
     for( i = 0; i < ki->exclude_file.count; i++ ) {
       ak_list list = &ki->exclude_file.list[i];
       if( list->count ) {
         ak_list_first( list );
         do{
             ak_keypair kp = (ak_keypair)list->current->data;
             ak_error_message_fmt( ak_error_ok, __func__, " - %s", (char *)kp->data );
         } while( ak_list_next( list ));
       }
     }
   }

  /* установленные пользователем настройки программы */
   if( strlen( ki->pubkey_file ) != 0 )
     ak_error_message_fmt( ak_error_ok, __func__, _("checksum database: %s"), ki->pubkey_file );
}

/* ----------------------------------------------------------------------------------------------- */
/*                              вывод справочной информации                                        */
/* ----------------------------------------------------------------------------------------------- */
 int aktool_icode_help( void )
{
  printf(_("aktool icode [options] [files or directories] - creation and verification of integrity codes\n\n"));
  printf(_("available options:\n"));
  printf(_(" -a, --algorithm         set the name or identifier of keyless integrity mechanism\n"));
  printf(_("                         [ enabled values:"));
 /* выводим перечень доступных идентификаторов */
  ak_oid oid = ak_oid_find_by_engine( hash_function );
  while( oid != NULL ) {
    printf(" %s", oid->name[0] );
    oid = ak_oid_findnext_by_engine( oid, hash_function );
  }
  printf(_(", default: %s ]\n"), ki.method->name[0] );
  printf(_("                         for keyed authentication mechanism use --key option\n"));
  printf(_(" -c, --config            specify the name of the configuration file\n"));
  printf(_("     --dont-show-icode   don't output calculated authentication or integrity codes to the console\n"));
  printf(_("     --dont-show-stat    don't show a statistical results after creation or verification of integrity codes\n"));
  printf(_(" -e, --exclude           specify the name of excluded files or directories\n"));
  printf(_("     --format            set the format of output hash table [ enabled values: binary linux bsd, default: binary ]\n"));
  printf(_("     --hash-table-nodes  number of high-level nodes in the generated hash table [ default: %llu ]\n"),
                                                                  (unsigned long long int) ki.icode_lists_count );
  printf(_("     --inpass            set the password for the secret key to be read directly in command line\n"));
  printf(_("     --inpass-hex        set the password for the secret key to be read directly in command line as hexademal string\n"));
  printf(_("     --key               specify the name of file with the secret key\n"));
  printf(_("                         this option also sets the type of keyed authentication mechanism\n"));
  printf(_("     --no-derive         do not use the keyed authentication mechanism's derived key for each controlled entity\n"));
  printf(_("                         this may cause an error due to the exhaustion of a key resource\n"));
#ifdef AK_HAVE_GELF_H
  printf(_("     --only-one-pid      verify only one process with given identifier (pid)\n"));
  printf(_("     --only-segments     create or verify authentication or integrity codes only for downloadable segments\n"));
#endif
  printf(_(" -o, --output            set the output file for created authentication or integrity codes\n"));
  printf(_(" -p, --pattern           set the pattern which is used to find files\n"));
#ifdef AK_HAVE_GELF_H
  printf(_("     --pid               short form of --only-one-pid option\n"));
#endif
  printf(_(" -r, --recursive         recursive search of files\n"));
  printf(_("     --reverse-order     output of authentication or integrity code in reverse byte order\n"));
  printf(_("     --tag               create a BSD-style hash table format\n"));
  printf(_(" -v, --verify            verify previously created authentication or integrity codes\n"));
#ifdef AK_HAVE_GELF_H
  printf(_("     --with-segments     create or verify authentication or integrity codes for downloadable segments\n"));
#endif

  aktool_print_common_options();

  printf(_("for usage examples try \"man aktool\"\n" ));
 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                 aktool_icode.c  */
/* ----------------------------------------------------------------------------------------------- */
