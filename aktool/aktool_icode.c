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
  int aktool_icode_ini_control( aktool_ki_t * , const char * , const char * , const char * );
  int aktool_icode_ini_handler( void * , const char * , const char * , const char * );
 void aktool_icode_log_options( aktool_ki_t * );
  int aktool_icode_hash( aktool_ki_t * );
  int aktool_icode_create_handle( aktool_ki_t * );
  int aktool_icode_destroy_handle( aktool_ki_t * );
  ak_pointer aktool_icode_get_derived_key( const char * , aktool_ki_t * );
  void aktool_icode_hash_out( FILE * , const char * , aktool_ki_t * , ak_uint8 * , const size_t );
  int aktool_icode_export_checksum( aktool_ki_t * );

/* ----------------------------------------------------------------------------------------------- */
/*! формат сохранения файла с вычисленными значениями */
 typedef enum
{
   format_binary = 0x0,
   format_linux = 0x01,
   format_bsd = 0x02
} aktool_icode_format_t;

/* ----------------------------------------------------------------------------------------------- */
 int aktool_icode( int argc, tchar *argv[] )
{
  int next_option = 0, exit_status = EXIT_FAILURE;
  enum { do_nothing, do_hash, do_check } work = do_hash;

  const struct option long_options[] = {
   /* сначала уникальные */
     { "algorithm",           1, NULL,  'a' },
     { "config",              1, NULL,  221 },
     { "exclude",             1, NULL,  'e' },
     { "pattern",             1, NULL,  'p' },
     { "recursive",           0, NULL,  'r' },
     { "reverse-order",       0, NULL,  254 },
     { "tag",                 0, NULL,  250 },
     { "hash-table-nodes",    1, NULL,  222 },
     { "output",              1, NULL,  'o' },
     { "no-derive",           0, NULL,  160 },
     { "dont-show-stat",      0, NULL,  161 },
     { "ignore-errors",       0, NULL,  162 },
     { "format",              1, NULL,  163 },
#ifdef AK_HAVE_GELF_H
     { "with-segments",       0, NULL,  164 },
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

 /* разбираем опции командной строки */
  do {
       next_option = getopt_long( argc, argv, "he:rp:o:a:", long_options, NULL );
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

        case 221 : /* устанавливаем имя конфигурационного файла */
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

        case 160: /* --no-derive */
                   ki.key_derive = ak_false;
                   break;

        case 161: /* --dont-show-stat */
                   ki.dont_show_stat = ak_true;
                   break;

        case 162: /* --ignore-errors */
                   ki.ignore_errors = ak_true;
                   break;

        case 163: /* --format устанавливаем формат хранения вычисленных/проверочных значений */
                   if( memcmp( optarg, "bsd", 3 ) == 0 ) ki.field = format_bsd;
                   if( memcmp( optarg, "linux", 5 ) == 0 ) ki.field = format_linux;
                   break;

#ifdef AK_HAVE_GELF_H
        case 164: /* --with-segments */
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
     /* выполняем вычисления */
      if(( exit_status = aktool_icode_hash( &ki )) != EXIT_SUCCESS ) goto exitlab;
     /* сохраняем результат */
      exit_status = aktool_icode_export_checksum( &ki );
      break;

    case do_check:
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
/*                          функции для сохранения/чтения контрольных сумм                         */
/* ----------------------------------------------------------------------------------------------- */
 int aktool_icode_export_checksum( aktool_ki_t *ki )
{
    size_t i = 0;
    FILE *fp = NULL;
    int exit_status = EXIT_FAILURE;

   /* определяемся с выводом в формате bsd */
    if( ki->tag ) ki->field = format_bsd;
    if( ki->field == format_bsd ) ki->tag = ak_true;

    switch( ki->field ) {

      case format_binary:
        if( ak_htable_export_to_file( &ki->icodes, ki->pubkey_file ) != ak_error_ok )
          aktool_error(_("incorrectly writing results to a file %s"), ki->pubkey_file );
         else {
           exit_status = EXIT_SUCCESS;
         }
        break;

      default: /* выводим в текстовом формате */
        if(( fp = fopen( ki->pubkey_file, "w" )) == NULL ) {
          aktool_error(_("incorrect output checksum to file %s"), ki->pubkey_file );
          break;
        }

        for( i = 0; i < ki->icodes.count; i++ ) {
           ak_list list = &ki->icodes.list[i];
           if( list->count == 0 ) continue;
           ak_list_first( list );
           do{
                ak_keypair kp = (ak_keypair)list->current->data;
                aktool_icode_hash_out( fp, (const char *)kp->data,
                                                   ki, kp->data+kp->key_length, kp->value_length );
           } while( ak_list_next( list ));
        }

        fclose(fp);
        exit_status = EXIT_SUCCESS;
        break;
    }

    if( exit_status == EXIT_SUCCESS ) {
      if(( !ki->quiet ) && ( !ki->dont_show_stat ))
             printf(_("all results saved in %s%s%s file\n"),
                          ak_error_get_start_string(), ki->pubkey_file, ak_error_get_end_string());
    }

 return exit_status;
}

/* ----------------------------------------------------------------------------------------------- */
/*                          функции для вычисления контрольных сумм                                */
/* ----------------------------------------------------------------------------------------------- */
 void aktool_icode_hash_out( FILE *fp, const char *value,
                                            aktool_ki_t *ki, ak_uint8 *buffer, const size_t size )
{
    if( ki->tag ) { /* вывод bsd */
     fprintf( fp, "%s (%s) = %s\n", ki->method->name[0], value,
                                              ak_ptr_to_hexstr( buffer, size, ki->reverse_order ));
    }
     else { /* вывод линуксовый */
      fprintf( fp, "%s %s\n", ak_ptr_to_hexstr( buffer, size, ki->reverse_order ), value );
     }
}

/* ----------------------------------------------------------------------------------------------- */
 ak_pointer aktool_icode_get_derived_key( const char *value, aktool_ki_t *ki )
{
    ak_pointer dkey = NULL;

   /* проверяем надо ли делать производный ключ */
    if(( ki->method->engine == hash_function ) || ( ki->key_derive == ak_false ))
      dkey = ki->handle;
     else {
        ak_oid koid = ((ak_skey)ki->handle)->oid;
       /* имеем секретный ключ, надо сделать производный того же типа */
        if(( dkey = ak_skey_new_derive_kdf256_from_skey(
                       koid,                           /* идентификатор создаваемого ключа */
                       ki->handle,                                        /* исходный ключ */
                       (ak_uint8*) value, /* метка, в качестве которой выступает имя файла */
                       strlen( value ),                                     /* длина метки */
                       NULL, 0 )) == NULL ) {
          aktool_error(_("incorrect creation of derivative key (file %s)"), value );
          return NULL;
        }
       /* подправляем ресурс ключа алгоритма блочного шифрования
          в противном случае придется вырабатывать следующий производный ключ и т.д. */
        if( koid->engine == block_cipher ) {
          struct file fp;
          ssize_t blocks = 0;

          ak_file_open_to_read( &fp, value );
          if(( blocks = (fp.size / ki->size )) > ((ak_skey)dkey)->resource.value.counter ) {
            ((ak_skey)dkey)->resource.value.counter = blocks;
            if( ak_log_get_level() > ak_log_standard ) {
              ak_error_message_fmt( ak_error_ok, __func__,
                _("the resource of the derived key was increased up to %ju blocks (file %s)"),
                                       (uintmax_t)((ak_skey)dkey)->resource.value.counter, value );
            }
          }
          ak_file_close( &fp );
        }
     }

  return dkey;
}

/* ----------------------------------------------------------------------------------------------- */
#ifdef AK_HAVE_GELF_H
 static int aktool_icode_hash_gelf( const char *value, aktool_ki_t *ki )
{
    Elf *e;
    size_t i, n;
    GElf_Phdr phdr;
    struct file fp;
    ak_uint8 icode[256];
    ak_uint8 *ptr = NULL;
    ak_pointer dkey = NULL;
    int error = ak_error_ok;
    char segment_value[FILENAME_MAX];

    if( ak_file_open_to_read( &fp, value ) != ak_error_ok ) return error;

    if(( e = elf_begin( fp.fd, ELF_C_READ, NULL )) == NULL ) {
      ak_file_close( &fp );
      return ak_error_message_fmt( ak_error_access_file, __func__,
                                             _("elf_begin() function failed: %s"), elf_errmsg(-1));
    }

   /* в случае выполнения данного условия файл является исполняемым */
    if( elf_kind(e) != ELF_K_ELF ) goto labexit;
   /* статистика */
    ki->statistical_data.executables++;

   /* определяем общее количество сегментов (программных заголовков) */
    if( elf_getphdrnum(e, &n) != 0 ) {
      error = ak_error_message_fmt( ak_error_access_file, __func__,
                                        _("elf_getphdrnum() function failed: %s"), elf_errmsg(-1));
      goto labexit;
    }
   /* последовательно обрабатываем каждый сегмент */
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

     /* обрабатываем найденный фрагмент */
      if(( ptr = ak_file_mmap( &fp, NULL, phdr.p_filesz,
                                              PROT_READ, MAP_PRIVATE, phdr.p_offset )) == NULL ) {
        error = ak_error_message_fmt( ak_error_mmap_file, __func__, "mmap error" );
        ki->statistical_data.skipped_executables++;
        goto labexit;
      }
     /* формируем фиртуальное имя файла - ключ доступа в виртуальной таблице */
      ak_snprintf( segment_value, sizeof( segment_value ) -1, "%s/%08jx", value, phdr.p_offset );
     /* при необходимости, формируем производный ключ */
      if(( dkey = aktool_icode_get_derived_key( segment_value, ki )) == NULL ) {
        ki->statistical_data.skipped_executables++;
        error = ak_error_null_pointer;
        goto labexit;
      }
     /* вычисляем контрольную сумму от заданного файла и помещаем ее в таблицу */
      memset( icode, 0, sizeof( icode ));
      ((ak_uint64 *)icode)[0] = phdr.p_filesz;
      error = ki->icode_ptr( dkey, ptr, phdr.p_filesz, icode +8, ki->size );
      if( dkey != ki->handle ) ak_skey_delete( dkey );
     /* проверка результата и его сохнение в хеш-таблице */
      if( error == ak_error_ok ) {
        if( !ki->quiet ) aktool_icode_hash_out( stdout, segment_value, ki, icode, ki->size +8 );
        ak_htable_add_str_value( &ki->icodes, segment_value, icode, ki->size +8 );
      }
       else {
         ki->statistical_data.skipped_executables++;
         ak_file_unmap( &fp );
         goto labexit;
       }

      ak_file_unmap( &fp );
    } /* конец for */

  labexit:
    (void) elf_end( e );
    ak_file_close( &fp );

  return error;
}
#endif

/* ----------------------------------------------------------------------------------------------- */
 static int aktool_icode_hash_function( const char *value, ak_pointer ptr )
{
    ak_uint8 icode[256];
    aktool_ki_t *ki = ptr;
    ak_pointer dkey = NULL;
    int error = ak_error_ok;

   /* проверяем черный список */
    if( ak_htable_get_str( &ki->exclude_file, value, NULL ) != NULL ) return ak_error_ok;
   /* статистика */
    ki->statistical_data.total_files++;
   /* вычисляем производный ключ */
    if(( dkey = aktool_icode_get_derived_key( value, ki )) == NULL ) {
      ki->statistical_data.skiped_files++;
      return ak_error_null_pointer;
    }
   /* вычисляем контрольную сумму от заданного файла и помещаем ее в таблицу */
    error = ki->icode_file( dkey, value, icode, ki->size );
    if( dkey != ki->handle ) ak_skey_delete( dkey );
   /* проверка результата и его сохнение в хеш-таблице */
    if( error == ak_error_ok ) {
      ki->statistical_data.hashed_files++;
      if( !ki->quiet ) aktool_icode_hash_out( stdout, value, ki, icode, ki->size );
      ak_htable_add_str_value( &ki->icodes, value, icode, ki->size );
    }
     else {
       ki->statistical_data.skiped_files++;
       goto labexit;
     }

   /* теперь приступаем к разбору исполняемых файлов */
  #ifdef AK_HAVE_GELF_H
   if( !ki->ignore_segments ) error = aktool_icode_hash_gelf( value, ki );
  #endif

   labexit:
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_icode_hash( aktool_ki_t *ki )
{
    tchar *value = NULL;
    int exit_status = EXIT_SUCCESS;

   /* обнуляем счетчики */
    memset( &ki->statistical_data, 0, sizeof( struct icode_stat ));

   /* проверяем, что данные для обработки заданы пользователем */
    if(( ki->include_file.count + ki->include_path.count ) == 0 ) {
      aktool_error(_("the name of file or directory must be specified"));
      return EXIT_FAILURE;
    }

   /* создаем контекст алгоритма хеширования или имитозащиты */
    if( aktool_icode_create_handle( ki ) != ak_error_ok ) return EXIT_FAILURE;

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

    if(( !ki->quiet ) && ( !ki->dont_show_stat )) {
      printf(_("\nthe total number of files found: %ju, of which:\n"),
                                                     (uintmax_t)ki->statistical_data.total_files );
      printf(_(" %6ju have been discarded\n"), (uintmax_t)ki->statistical_data.skiped_files );
      printf(_(" %6ju have been proceed\n"), (uintmax_t)ki->statistical_data.hashed_files );
    #ifdef AK_HAVE_GELF_H
      printf(_(" %6ju contain downloadable segments\n"),
                                                     (uintmax_t)ki->statistical_data.executables );
      if( ki->statistical_data.skipped_executables )
        printf(_(" %6ju downloadable segments discarded\n"),
                                             (uintmax_t)ki->statistical_data.skipped_executables );
    #endif
   }

   if( ki->statistical_data.skiped_files ) {
     exit_status = EXIT_FAILURE;
     aktool_error(_("aktool found %d error(s), try aktool with \"--audit-file stderr --audit 2\""
                           " options or see syslog messages"), ki->statistical_data.skiped_files );
   }
   aktool_icode_destroy_handle( ki );

  return exit_status;
}

/* ----------------------------------------------------------------------------------------------- */
/*                 Функция для создания и удаления ключевой информации                             */
/* ----------------------------------------------------------------------------------------------- */
 int aktool_icode_create_handle( aktool_ki_t *ki )
{
    ak_oid koid = NULL;
    char oidstr[32];

   /* начинаем с того, что проверяем, задан алгоритм хеширования или имитозащиты */
    if( strlen( ki->key_file ) == 0 ) {
     /* создаем алгоритм хеширования */
      if(( ki->handle = ak_oid_new_object( ki->method )) == NULL ) {
        aktool_error(_("wrong creation of internal context of %s algorithm"), ki->method->name[0]);
        return ak_error_get_value();
      }
     /* устанавливаем указатели на обработчики */
      ki->icode_file = ( ak_function_icode_file *) ak_hash_file;
     #ifdef AK_HAVE_GELF_H
      ki->icode_ptr = ( ak_function_icode_ptr *) ak_hash_ptr;
     #endif

      ki->size = ak_hash_get_tag_size( ki->handle );
      return ak_error_ok;
    }

   /* остальное посвящаем обработке алгоритмов имитозащиты */
    ak_libakrypt_set_password_read_function( aktool_load_user_password );
    if(( ki->handle = ak_skey_load_from_file( ki->key_file )) == NULL ) {
      aktool_error(_("wrong reading a secret key from %s file"), ki->key_file );
      return ak_error_get_value();
    }

    if(( koid = ((ak_skey)ki->handle)->oid ) == NULL ) {
      ak_skey_delete( ki->handle );
      aktool_error(_("null pointer to a secret key oid (%s file)"), ki->key_file );
      return ak_error_null_pointer;
    }

   /* устанавливаем обработчики */
    switch( koid->engine ) {
       case hmac_function:
         ki->icode_file = ( ak_function_icode_file *) ak_hmac_file;
       #ifdef AK_HAVE_GELF_H
         ki->icode_ptr = ( ak_function_icode_ptr *) ak_hmac_ptr;
       #endif
         ki->size = ak_hmac_get_tag_size( ki->handle );
         ki->method = koid;
         break;

       case block_cipher:
        /* сейчас поддерживается только имитовставка по ГОСТ Р 34.13-2015,
           далее можно подумать о применении, например, aead режимов */
         ak_snprintf( oidstr, sizeof( oidstr ), "cmac-%s", koid->name[0] );
         if(( ki->method = ak_oid_find_by_name( oidstr )) == NULL ) {
           aktool_error(_("unexpected block cipher identifier (%s)"), oidstr );
           return ak_error_oid_name;
         }
         ki->icode_file = ( ak_function_icode_file *) ak_bckey_cmac_file;
        #ifdef AK_HAVE_GELF_H
         ki->icode_ptr = ( ak_function_icode_ptr *) ak_bckey_cmac;
        #endif
         ki->size = ((ak_bckey)ki->handle)->bsize;
         break;

       default:
        ak_skey_delete( ki->handle );
        aktool_error(
                _("using a secret key with unsupported type of authentication mechanism (%s)"),
                                                                                   koid->name[0] );
        return ak_error_key_usage;
    }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_icode_destroy_handle( aktool_ki_t *ki )
{
    if( ki->method->engine == hash_function )
      ak_oid_delete_object( ki->oid_of_target, ki->handle );
     else
      ak_skey_delete( ki->handle );

 return ak_error_ok;
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
 int aktool_icode_ini_control( aktool_ki_t *ki,
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
 int aktool_icode_ini_handler( void *user,
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
  printf(_("     --config            specify the name of the configuration file\n"));
  printf(_("     --dont-show-stat    don't show a statistical results after calculating/checking of integrity codes\n"));
  printf(_(" -e, --exclude           specify the name of excluded files or directories\n"));
  printf(_("     --format            set the format of output file [ enabled values: binary linux bsd, default: binary ]\n"));
  printf(_("     --hash-table-nodes  number of high-level nodes in the generated hash table [ default: %llu ]\n"),
                                                                  (unsigned long long int) ki.icode_lists_count );
  printf(_("     --ignore-errors     don't break a check for new, missing and corrupted files\n"));
  printf(_("     --inpass            set the password for the secret key to be read directly in command line\n"));
  printf(_("     --inpass-hex        set the password for the secret key to be read directly in command line as hexademal string\n"));
  printf(_("     --key               specify the name of file with the secret key\n"));
  printf(_("                         this option also sets the type of keyed authentication mechanism\n"));
  printf(_("     --no-derive         do not use the keyed authentication mechanism's derived key for each controlled entity\n"));
  printf(_("                         this may cause an error due to the exhaustion of a key resource\n"));
  printf(_(" -o, --output            set the output file for generated authentication or integrity codes\n"));
  printf(_(" -p, --pattern           set the pattern which is used to find files\n"));
  printf(_(" -r, --recursive         recursive search of files\n"));
  printf(_("     --reverse-order     output of authentication or integrity code in reverse byte order\n"));
  printf(_("     --tag               create a BSD-style checksum format\n"));
#ifdef AK_HAVE_GELF_H
  printf(_("     --with-segments     calculate authentication or integrity codes for downloadable segments\n"));
#endif

//  printf(_("     --seed              set the initial value for key derivation function (when used)\n"));
//  printf(_("     --derive-function   установить свою функцию выработки производного ключа \n"));
//  printf(_(" -c, --check             check previously generated authentication or integrity codes\n"
  aktool_print_common_options();

  printf(_("for usage examples try \"man aktool\"\n" ));
 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                 aktool_icode.c  */
/* ----------------------------------------------------------------------------------------------- */
