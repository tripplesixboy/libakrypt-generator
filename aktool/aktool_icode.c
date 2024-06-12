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
#ifdef AK_HAVE_UNISTD_H
 #include <unistd.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
 int aktool_icode_help( void );
 int aktool_icode_read_config( char *, aktool_ki_t * );
 static int aktool_icode_ini_control( aktool_ki_t * , const char * , const char * , const char * );
 static int aktool_icode_ini_handler( void * , const char * , const char * , const char * );
 void aktool_icode_log_options( aktool_ki_t * );
 void aktool_icode_hash( aktool_ki_t * );

/* ----------------------------------------------------------------------------------------------- */
 int aktool_icode( int argc, tchar *argv[] )
{
  int next_option = 0, exit_status = EXIT_FAILURE;
  enum { do_nothing, do_hash, do_check } work = do_hash;

  const struct option long_options[] = {
   /* сначала уникальные */
     { "config",              1, NULL,  221 },
     { "exclude",             1, NULL,  'e' },
     { "pattern",             1, NULL,  'p' },
     { "recursive",           0, NULL,  'r' },
     { "reverse-order",       0, NULL,  254 },
     { "tag",                 0, NULL,  250 },
     { "hash-table-nodes",    1, NULL,  222 },
     { "output",              1, NULL,  'o' },

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

 /* разбираем опции командной строки */
  do {
       next_option = getopt_long( argc, argv, "he:rp:o:", long_options, NULL );
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

        case 222 : /* --hash-table-nodes устанавливаем количество узлов верхнего уровня в хеш-таблице
                      результирующее значение всегда находится между 16 и 4096 */
                   ki.icode_lists_count = ak_min( 4096, ak_max( 16, atoi( optarg )));
                   break;

        case 'o' : /* --output устанавливаем имя файла c результатами вычислений */
                  #ifdef _WIN32
                   GetFullPathName( optarg, FILENAME_MAX, ki.pubkey_file, NULL );
                  #else
                   if( ak_realpath( optarg, ki.pubkey_file, sizeof( ki.pubkey_file ) -1 ) != ak_error_ok ) {
                     aktool_error(_("the full name of file with generated authentication codes cannot be created"));
                     return EXIT_FAILURE;
                   }
                  #endif
                   break;


        case 'e' : /* --exclude устанавливаем имя исключаемого файла или каталога */
                   aktool_icode_ini_control( &ki, "", "exclude", optarg );
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

        default:  /* обрабатываем ошибочные параметры */
                   if( next_option != -1 ) return EXIT_FAILURE;
                   break;
      }

  } while( next_option != -1 );

 /* завершаем обработку параметров без флагов
    все они интерпретируются как файлы или каталоги для контроля целостности */
  ++optind; /* пропускаем команду - i или icode */
 /* начинаем цикл добавления файлов и каталогов, указанных пользователем */
  while( optind < argc ) aktool_icode_ini_control( &ki, "", "", argv[optind++] );

 /* начинаем работу с криптографическими примитивами */
  if( !aktool_create_libakrypt( )) goto exitlab;

 /* считываем оставшиеся конфигурационные настройки из заданного файла */
  if( strlen( ki.capubkey_file ) > 0 ) {
    if(( exit_status = aktool_icode_read_config( ki.capubkey_file, &ki )) != ak_error_ok )
      goto exitlab;
  }

 /* разбираемся с именем файла для сохранения результатов */
  if( strlen( ki.pubkey_file ) == 0 ) {
   #ifdef _WIN32
     GetFullPathName( "aktool.icodes", FILENAME_MAX, ki.pubkey_file, NULL );
    #else
     ak_realpath( "/var/tmp/aktool.icodes", ki.pubkey_file, sizeof( ki.pubkey_file ) -1 );
    #endif
  }

 /* создаем или считываем таблицу для хранения контрольных сумм */
  if( ak_htable_create( &ki.icodes, ki.icode_lists_count ) != ak_error_ok ) goto exitlab;

 /* выполняем аудит настроек перед запуском программы  */
  aktool_icode_log_options( &ki );

 /* теперь выбираем, что делать */
  switch( work ) {
    case do_hash:
      aktool_icode_hash( &ki );
      break;
    case do_check:
      break;
    default:
      break;
  }

 /* сохраняем результат */
  if( ak_htable_export_to_file( &ki.icodes, ki.pubkey_file ) != ak_error_ok )
    aktool_error(_("incorrectly writing results to a file %s"), ki.pubkey_file );

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
/*                          функции для вычисления контрольных сумм                                */
/* ----------------------------------------------------------------------------------------------- */
 static int aktool_icode_hash_out( const char *value, aktool_ki_t *ki,
                                                              ak_uint8 *buffer, const size_t size )
{
    if( ki->quiet ) return ak_error_ok;

    if( ki->tag ) { /* вывод bsd */
     fprintf( stdout, "%s (%s) = %s\n", "st->oid->name[0]", value,
                                           ak_ptr_to_hexstr( buffer, size, ki->reverse_order ));
    } else { /* вывод линуксовый */
       fprintf( stdout, "%s %s\n", ak_ptr_to_hexstr( buffer, size, ki->reverse_order ), value );
      }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
#ifdef AK_HAVE_GELF_H
 static int aktool_icode_hash_gelf( const char *value, aktool_ki_t *ki )
{
    Elf *e;
    size_t i, n;
    struct file fp, fp2;
    int error = ak_error_ok;
    GElf_Phdr phdr;

    if( ak_file_open_to_read( &fp, value ) != ak_error_ok ) return error;

    if(( e = elf_begin( fp.fd, ELF_C_READ, NULL )) == NULL ) {
      ak_file_close( &fp );
      return ak_error_message_fmt( ak_error_access_file, __func__,
                                             _("elf_begin() function failed: %s"), elf_errmsg(-1));
    }

   /* в случае выполнения данного условия файл является исполняемым */
    if( elf_kind(e) != ELF_K_ELF ) goto labexit;

   /* определяем общее количество сегментов (программных заголовков) */
    if( elf_getphdrnum(e, &n) != 0 ) {
      error = ak_error_message_fmt( ak_error_access_file, __func__,
                                        _("elf_getphdrnum() function failed: %s"), elf_errmsg(-1));
      goto labexit;
    }
    printf("%s has %lu headers\n", value, n );

    for( i = 0; i < n; i++ ) {
      if( gelf_getphdr( e, i, &phdr ) != &phdr ) {
        error = ak_error_message_fmt( ak_error_access_file, __func__,
                                          _("gelf_getphdr() function failed: %s"), elf_errmsg(-1));
        goto labexit;
      }
     /* ищем только загружаемые сегменты */
      if( phdr.p_type != PT_LOAD ) continue;
     /* ищем только неисполняемые сегменты */
      if( phdr.p_flags & PF_W ) continue;

      // ak_hash_file
      // ak_hmac_file
      // ak_bckey_cmac_file

   /* xxx */
    size_t size = 32;
    ak_uint8 icode[128];
    struct hash ctx;
    ak_hash_create_streebog256( &ctx );



      printf("[offset: %jx, size: %jx (%lu), flags: %jx]\n", phdr.p_offset, phdr.p_filesz, phdr.p_filesz, phdr.p_flags );

//      ak_file_open_to_read( &fp2, value );
      ak_uint8 *ptr = ak_file_mmap( &fp, NULL, phdr.p_filesz, PROT_READ, MAP_PRIVATE, phdr.p_offset );

      ak_hash_ptr( &ctx, ptr, phdr.p_filesz, icode, size );
      aktool_icode_hash_out( value, ki, icode, size );
      //ak_htable_add_str_value( &ki->icodes, value, icode, size );

//      ak_file_unmap( &fp2 );
//      ak_file_close( &fp2 );

    ak_hash_destroy( &ctx );

      }

  labexit:
    (void) elf_end( e );
    ak_file_close( &fp );

  return error;
}
#endif

/* ----------------------------------------------------------------------------------------------- */
 static int aktool_icode_hash_function( const char *value, ak_pointer ptr )
{
    size_t size = 32;
    ak_uint8 icode[128];
    aktool_ki_t *ki = ptr;
    int error = ak_error_ok;

   /* проверяем черный список */
    if( ak_htable_get_str( &ki->exclude_file, value, NULL ) != NULL ) return ak_error_ok;

   /* xxx */
    struct hash ctx;
    ak_hash_create_streebog256( &ctx );

   /* сперва вычисляем контрольную сумму от заданного файла и помещаем ее в таблицу */
    if(( error = ak_hash_file( &ctx, value, icode, size )) == ak_error_ok ) {
      aktool_icode_hash_out( value, ki, icode, size );
      ak_htable_add_str_value( &ki->icodes, value, icode, size );
    }
     else {
       ki->errcount++;
       goto labexit;
     }

   /* теперь приступаем к разбору исполняемых файлов */
  #ifdef AK_HAVE_GELF_H
   if(( error = aktool_icode_hash_gelf( value, ki )) != ak_error_ok ) ki->errcount++;
  #endif

   /* xxx: запускаем вычисление контрольной суммы */
   labexit:
    ak_hash_destroy( &ctx );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 void aktool_icode_hash( aktool_ki_t *ki )
{
    tchar *value = NULL;

   /* обнуляем счетчики */
    ki->errcount = 0;

   /* начинаем с обхода файлов */
    if( ki->include_file.count ) {
      ak_list_first( &ki->include_file );
      do{
          aktool_icode_hash_function(( char * )ki->include_file.current->data, ki );
      } while( ak_list_next( &ki->include_file ));
    }

   /* теперь продолжаем обходом каталогов */
    if( ki->include_path.count ) {
      ak_list_first( &ki->include_path );
      do{
          value = ( char * )ki->include_path.current->data;
         /* проверяем черный список */
          if( ak_htable_get_str( &ki->exclude_path, value, NULL ) != NULL ) continue;
         /* запускаем вычисление контрольной суммы */
          ak_file_find( value, ki->pattern, aktool_icode_hash_function, ki, ki->tree );
      } while( ak_list_next( &ki->include_path ));
    }

   if( ki->errcount ) {
     if( !ki->quiet ) aktool_error(_("aktool found %d error(s), "
           "rerun aktool with \"--audit-file stderr --audit 2\" "
                                                 "options or see syslog messages"), ki->errcount );
   }
}

/* ----------------------------------------------------------------------------------------------- */
/*                 функции для чтения и проверки корректности файла с конфигурацией                */
/* ----------------------------------------------------------------------------------------------- */
 static int aktool_icode_ini_options( aktool_ki_t *ki,
                                         const char *section, const char *name, const char *value )
{
   /* флаг рекурсивного обхода каталогов */
    if( memcmp( name, "recursive", 9 ) == 0 ) {
      if(( memcmp( value, "true", 4 ) == 0 ) || ( memcmp( value, "TRUE", 4 ) == 0 ))
        ki->tree = ak_true;
    }
   /* шаблон поиска файлов */
    if( memcmp( name, "pattern", 7 ) == 0 ) {
      if( ki->pattern != NULL ) free( ki->pattern );
      ki->pattern = strdup( value );
    }

  return 1;
}

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
 /* обрабатываем дополнительные параметры */
  if( memcmp( section, "options", 7 ) == 0 )
    return aktool_icode_ini_options( ki, section, name, value );

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
}

/* ----------------------------------------------------------------------------------------------- */
/*                              вывод справочной информации                                        */
/* ----------------------------------------------------------------------------------------------- */
 int aktool_icode_help( void )
{
  printf(_("aktool icode [options] [files or directories] - calculation and verification of integrity codes\n\n"));
  printf(_("available options:\n"));
  printf(_("     --config            specify the name of the configuration file\n"));
  printf(_(" -e, --exclude           specify the name of excluded files or directories\n"));
  printf(_("     --hash-table-nodes  number of high-level nodes in the generated hash table [ default: %llu ]\n"),
                                                                  (unsigned long long int) ki.icode_lists_count );
  printf(_(" -o, --output            set the output file for generated authentication or integrity codes\n"));
  printf(_(" -p, --pattern           set the pattern which is used to find files\n"));
  printf(_(" -r, --recursive         recursive search of files\n"));
  printf(_("     --reverse-order     output of authentication or integrity code in reverse byte order\n"));
  printf(_("     --tag               create a BSD-style checksum format\n"));

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
  //    "
  //    "     --seed              set the initial value of key derivation functions (used only for file authentication)\n"
  //    "
  // ));
  aktool_print_common_options();

  printf(_("for usage examples try \"man aktool\"\n" ));
 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                 aktool_icode.c  */
/* ----------------------------------------------------------------------------------------------- */
