/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2018 - 2021, 2024 by Axel Kenzo, axelkenzo@mail.ru                               */
/*                                                                                                 */
/*  Прикладной модуль, реализующий процедуры проверки целостности данных                           */
/*                                                                                                 */
/*  aktool_ikey.c                                                                                  */
/* ----------------------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <aktool.h>
#ifdef AK_HAVE_ERRNO_H
 #include <errno.h>
#endif
#ifdef AK_HAVE_GELF_H
 #include <gelf.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
 int aktool_icode_help( void );
 int aktool_icode_read_config( char *, aktool_ki_t * );
 static int aktool_icode_ini_handler( void * , const char * , const char * , const char * );
 void aktool_icode_log_options( aktool_ki_t * );

/* ----------------------------------------------------------------------------------------------- */
 int aktool_icode( int argc, tchar *argv[] )
{
  int next_option = 0, exit_status = EXIT_FAILURE;
  enum { do_nothing, do_hash, do_check } work = do_hash;

  const struct option long_options[] = {
   /* сначала уникальные */
     { "config",              1, NULL,  221 },

   /* это стандартые для всех программ опции */
     aktool_common_functions_definition,
     { NULL,                  0, NULL,   0  },
  };

 /* заполняем поля структуры с параметрами значениями по-умолчанию */
  memset( &ki, 0, sizeof( aktool_ki_t ));

 /* разбираем опции командной строки */
  do {
       next_option = getopt_long( argc, argv, "h", long_options, NULL );
       switch( next_option )
      {
        aktool_common_functions_run( aktool_icode_help );

        case 221 : /* устанавливаем имя конфигурационного файла */
                  #ifdef _WIN32
                   GetFullPathName( optarg, FILENAME_MAX, ki.capubkey_file, NULL );
                  #else
                   if( ak_realpath( optarg, ki.capubkey_file, sizeof( ki.capubkey_file ) -1 ) != ak_error_ok ) {
                     aktool_error(_("the full name of config file cannot be created"));
                     return EXIT_FAILURE;
                   }
                  #endif
                   break;

        default:  /* обрабатываем ошибочные параметры */
                   if( next_option != -1 ) return EXIT_FAILURE;
                   break;
      }

  } while( next_option != -1 );

 /* начинаем работу с криптографическими примитивами */
  if( !aktool_create_libakrypt( )) goto exitlab;

 /* считываем оставшиеся конфигурационные настройки из дананного файла */
  if( strlen( ki.capubkey_file ) > 0 ) {
    if(( exit_status = aktool_icode_read_config( ki.capubkey_file, &ki )) != ak_error_ok )
      goto exitlab;
  }

 /* выполняем аудит настроек перед запуском программы  */
  aktool_icode_log_options( &ki );

 /* теперь выбираем, что делать */
  switch( work ) {
    case do_hash:
     break;
    case do_check:
     break;
    default:
     break;
  }

 /* завершаем выполнение основного процесса */
  exitlab:
    ak_list_destroy( &ki.include_path );
    ak_list_destroy( &ki.exclude_path );
    ak_list_destroy( &ki.include_file );
    ak_list_destroy( &ki.exclude_file );
    aktool_destroy_libakrypt();
 return exit_status;
}

/* ----------------------------------------------------------------------------------------------- */
/*                 функции для чтения и проверки корректности файла с конфигурацией                */
/* ----------------------------------------------------------------------------------------------- */
 static int aktool_icode_ini_control( aktool_ki_t *ki,
                                         const char *section, const char *name, const char *value )
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
          if( ak_list_add_node( &(ki->exclude_path ),
                                       ak_list_node_new_string( value )) != ak_error_ok ) return 0;
           else return 1;
        case DT_REG:
          if( ak_list_add_node( &(ki->exclude_file ),
                                       ak_list_node_new_string( value )) != ak_error_ok ) return 0;
           else return 1;
        default:
          return 1;
      }
    }

 /* пропускаем строки с невнятным наполнением */
 return 1;
}

/* ----------------------------------------------------------------------------------------------- */
 static int aktool_icode_ini_handler( void *user,
                                         const char *section, const char *name, const char *value )
{
  aktool_ki_t *ki = user;

 /* проверяем указатели */
  if(( section == NULL ) || ( name == NULL ) || ( value == NULL )) {
    aktool_error(_("unexpected null-section in config file"));
    return 0;
  }
 /* обрабатываем списки файлов и каталогов */
  if( memcmp( section, "control", 7 ) == 0 )
    return aktool_icode_ini_control( ki, section, name, value );

  aktool_error("unsupported section: %s, name: %s, value: %s", section, name, value );
 return 1; /* ненулевое значение - успешное завершение обработчика */
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_icode_read_config( char *filename, aktool_ki_t *ki )
{
  int error = ak_error_ok;
  if(( error = ak_ini_parse( filename, aktool_icode_ini_handler, ki )) != ak_error_ok )
    aktool_error(_("incorrect parsing of config file"));

  return error;
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
   if( ki->include_path.count ) {
     ak_error_message( ak_error_ok, __func__, _("directory list:"));
     ak_list_first( &ki->include_path );
     do{
       ak_error_message_fmt( ak_error_ok, __func__,
                                                 " - %s", (char *)ki->include_path.current->data );
     } while( ak_list_next( &ki->include_path ));
   } else ak_error_message( ak_error_ok, "", _("directory list undefined"));
  /* файлы */
   if( ki->include_file.count ) {
     ak_error_message( ak_error_ok, __func__, _("file list:"));
     ak_list_first( &ki->include_file );
     do{
       ak_error_message_fmt( ak_error_ok, __func__,
                                                 " - %s", (char *)ki->include_file.current->data );
     } while( ak_list_next( &ki->include_file ));
   } else ak_error_message( ak_error_ok, "", _("file list undefined"));

  /* пропускаем каталоги и файлы */
   if( ki->exclude_path.count ) {
     ak_error_message( ak_error_ok, __func__, _("exclude directory:"));
     ak_list_first( &ki->exclude_path );
     do{
       ak_error_message_fmt( ak_error_ok, __func__,
                                                 " - %s", (char *)ki->exclude_path.current->data );
     } while( ak_list_next( &ki->exclude_path ));
   }
   if( ki->exclude_file.count ) {
     ak_error_message( ak_error_ok, __func__, _("exclude file:"));
     ak_list_first( &ki->exclude_file );
     do{
       ak_error_message_fmt( ak_error_ok, __func__,
                                                 " - %s", (char *)ki->exclude_file.current->data );
     } while( ak_list_next( &ki->exclude_file ));
   }
}

/* ----------------------------------------------------------------------------------------------- */
/*                              вывод справочной информации                                        */
/* ----------------------------------------------------------------------------------------------- */
 int aktool_icode_help( void )
{
  printf(_("aktool icode [options] [files or directories] - calculation and verification of integrity codes\n\n"));
  printf(_("available options:\n"));
  printf(_("     --config            specify the name of the configuration file\n"));



  //    " -a, --algorithm         set the name or identifier of integrity function (used only for integrity checking)\n"
  //    "                         default algorithm is \"streebog256\" defined by RFC 6986\n"
  //    " -c, --check             check previously generated authentication or integrity codes\n"
  //    "     --dont-show-stat    don't show a statistical results after checking\n"
  //    "     --ignore-errors     don't break a check if file is missing or corrupted\n"
  //    "     --inpass            set the password for the secret key to be read directly in command line\n"
  //    "     --inpass-hex        read the password for the secret key as hexademal string\n"
  //    "     --key               specify the name of file with the secret key\n"
  //    " -m, --mode              set the block cipher mode [enabled values: cmac-{cipher}]\n"
  //    "     --no-derive         do not use derived keys for file authentication\n"
  //    " -o, --output            set the output file for generated authentication or integrity codes\n"
  //    " -p, --pattern           set the pattern which is used to find files\n"
  //    " -r, --recursive         recursive search of files\n"
  //    "     --reverse-order     output of authentication or integrity code in reverse byte order\n"
  //    "     --seed              set the initial value of key derivation functions (used only for file authentication)\n"
  //    "     --tag               create a BSD-style checksum format\n"
  // ));
  aktool_print_common_options();

  printf(_("for usage examples try \"man aktool\"\n" ));
 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                 aktool_icode.c  */
/* ----------------------------------------------------------------------------------------------- */
