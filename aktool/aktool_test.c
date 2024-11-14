/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2018 - 2021 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Прикладной модуль, реализующий процедуры тестирования функций библиотеки libakrypt             */
/*                                                                                                 */
/*  aktool_test.c                                                                                  */
/* ----------------------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <aktool.h>

/* ----------------------------------------------------------------------------------------------- */
/* - запуск теста криптографических алгоритмов
       aktool test --crypto --audit 2 --audit-file stderr                                          */
/* ----------------------------------------------------------------------------------------------- */
 int aktool_test_help( void );
 int aktool_test_speed_mode( char * );
 int aktool_test_speed_name( char * );
 int aktool_test_speed_engine( char * );
 int aktool_test_speed_oid( int , ak_oid );

/* ----------------------------------------------------------------------------------------------- */
 static int aktool_test_speed_block_cipher( int, ak_oid );
 static int aktool_test_speed_hash_function( int, ak_oid );
 static int aktool_test_speed_hmac_function( int, ak_oid );
 static int aktool_test_speed_sign_function( int, ak_oid );

/* ----------------------------------------------------------------------------------------------- */
 bool_t large_array_test = ak_true;
 bool_t packets_test = ak_true;
 ak_uint32 min_length_mb = 16;
 ak_uint32 max_length_mb = 128;


/* ----------------------------------------------------------------------------------------------- */
 int aktool_test( int argc, tchar *argv[] )
{
  char *value = NULL;
  int next_option = 0, exit_status = EXIT_SUCCESS;

  enum { do_nothing, do_dynamic, do_speed_engine,
             do_speed_name, do_speed_mode, do_list_modes, do_list_engines } work = do_nothing;

  const struct option long_options[] = {
     { "crypto",           0, NULL, 255 },
     { "speed-by-engine",  1, NULL, 'e' },
     { "speed-by-name",    1, NULL, 'n' },
     { "speed-by-mode",    1, NULL, 'm' },
     { "list-modes",       0, NULL, 254 },
     { "list-engines",     0, NULL, 253 },
     { "no-large-arrays",  0, NULL, 249 },
     { "no-packets",       0, NULL, 248 },
     { "min-length",       1, NULL, 239 },
     { "max-length",       1, NULL, 238 },

     aktool_common_functions_definition,
     { NULL,               0, NULL,   0 }
  };

 /* разбираем опции командной строки */
  do {
       next_option = getopt_long( argc, argv, "he:n:m:", long_options, NULL );
       switch( next_option )
      {
        aktool_common_functions_run( aktool_test_help );

        case 255 : /* тест скорости функций хеширования */
                     work = do_dynamic;
                     break;

        case 'e': /* тест скорости для заданного типа криптографического алгоритма */
                     work = do_speed_engine; value = optarg;
                     break;
        case 'n': /* тест скорости по заданному фрагменту имени или идентификатора алгоритма */
                     work = do_speed_name; value = optarg;
                     break;
        case 'm': /* тест скорости по заданному режиму исопльзования алгоритма */
                     work = do_speed_mode; value = optarg;
                     break;
        case 254:    work = do_list_modes;
                     break;
        case 253:    work = do_list_engines;
                     break;

        case 249:    large_array_test = ak_false;
                     break;
        case 248:    packets_test = ak_false;
                     break;

        case 239:    if(( min_length_mb = atoi( optarg )) == 0 ) min_length_mb = 16;
                     break;
        case 238:    if(( max_length_mb = atoi( optarg )) == 0 ) max_length_mb = 128;
                     break;


        default:   /* обрабатываем ошибочные параметры */
                     if( next_option != -1 ) work = do_nothing;
                     break;
       }
   } while( next_option != -1 );
   if( work == do_nothing ) return aktool_test_help();

 /* начинаем работу с криптографическими примитивами */
   if( !aktool_create_libakrypt( )) return EXIT_FAILURE;

 /* выбираем заданное пользователем действие */
    switch( work )
   {
     case do_dynamic:
       if( ak_libakrypt_dynamic_control_test( )) {
         if( !ki.quiet ) printf(_("complete crypto test is Ok\n"));
       }
        else {
          aktool_error(_("complete crypto test is Wrong\n"));
          exit_status = EXIT_FAILURE;
        }
       break;

       case do_list_engines:
         printf(_("available engines: hash, hmac, cipher, sign\n"));
       break;

       case do_list_modes:
         printf(_("available modes: encrypt, encrypt2k, acpkm, mac, aead\n"));
       break;

       case do_speed_engine:
         exit_status = aktool_test_speed_engine( value );
         break;

       case do_speed_mode:
         exit_status = aktool_test_speed_mode( value );
         break;

       case do_speed_name:
         exit_status = aktool_test_speed_name( value );
         break;

     default:  break; /* конец switch( work ) */
   }

   if( exit_status == EXIT_FAILURE )
     if( !ki.quiet ) printf( _("for more information run test with \"--audit 2 --audit-file stderr\" options "
                                                                              "or see /var/log/auth.log file\n"));
 /* завершаем работу и выходим */
   aktool_destroy_libakrypt();

 return exit_status;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_test_help( void )
{
  printf(
   _("aktool test [options]  - run various tests\n\n"
     "available options:\n"
     "     --crypto            complete test of cryptographic algorithms\n"
     "                         run all available algorithms on test values taken from standards and recommendations\n"
     " -e, --speed-by-engine   measuring the speed of the all crypto algorithms defined by given engine\n"
     "     --list-engines      output a list of all supported engines\n"
     "     --list-modes        output a list of all supported modes\n"
     " -m, --speed-by-mode     mesuaring the speed of the crypto algorithms with given mode\n"
     "     --max-length        set the maximal length (in megabytes) of encrypted data [ default: %uMb]\n"
     "     --min-length        set the minimal length (in megabytes) of encrypted data [ default: %uMb]\n"
     " -n, --speed-by-name     measuring the speed of the given crypto algorithm\n"
     "                         a search is performed for all algorithms whose name contains the specified string\n"
     "     --no-large-arrays   do not run tests with large arrays of pseudorandom data\n"
     "     --no-packets        do not run tests with short network packets\n"
  ), max_length_mb, min_length_mb );
  aktool_print_common_options();

  printf(_("for usage examples try \"man aktool\"\n" ));
 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_test_speed_name( char *value )
{
 /* в этой фукнции поиск идентификаторов производится по имени или идентификатору,
    содержащему в своем составе заданный фрагмент */
  int returncode = EXIT_FAILURE, fc = 0;
  size_t idx, count = ak_libakrypt_oids_count() -1;
  for( idx = 0; idx < count; idx++ ) {
    int jdx;
    ak_oid oid = ak_oid_find_by_index( idx );
    if( oid == NULL ) return EXIT_FAILURE;

   /* поиск по идентификатору */
    jdx = 0;
    while( oid->id[jdx] != NULL ) {
      if( strstr( oid->id[jdx], value ) != NULL ) goto jump;
      ++jdx;
    }
   /* поиск по имени */
    jdx = 0;
    while( oid->name[jdx] != NULL ) {
      if( strstr( oid->name[jdx], value ) != NULL ) goto jump;
      ++jdx;
    }
    continue;
    jump:
      returncode = EXIT_SUCCESS;
      aktool_test_speed_oid( ++fc, oid );
  }
  if( returncode == EXIT_FAILURE ) {
    aktool_error(_("the string \"%s\" is not contained among the names or identifiers of the crypto algorithms"), value );
  }
 /* если ни чего не найдено, признак ошибки не возвращается */
  return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_test_speed_mode( char *value )
{
   ak_oid oid = NULL;
   oid_modes_t mode = undefined_mode;
   int exitcode = EXIT_FAILURE, fc = 0;

   if( strstr( "mac", value ) != NULL ) mode = mac;
   if( strstr( "aead", value ) != NULL ) mode = aead;
   if( strstr( "acpkm", value ) != NULL ) mode = acpkm;
   if( strstr( "encrypt", value ) != NULL ) mode = encrypt_mode;
   if( strstr( "encrypt2k", value ) != NULL ) mode = encrypt2k_mode;
   if( strstr( "algorithm", value ) != NULL ) mode = algorithm;

   if( mode != undefined_mode ) {
     oid = ak_oid_find_by_mode( mode );
     while( oid != NULL ) {
       exitcode = aktool_test_speed_oid( ++fc, oid );
       oid = ak_oid_findnext_by_mode( oid, mode );
     }
   }

  if( exitcode == EXIT_FAILURE )
    aktool_error(_("the string \"%s\" is not a supportable name of the crypto algorithm mode"), value );
  return exitcode;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_test_speed_engine( char *value )
{
   ak_oid oid = NULL;
   oid_engines_t engine = undefined_engine;
   int exitcode = EXIT_FAILURE, fc = 0;

   if( strstr( "block cipher", value ) != NULL ) engine = block_cipher;
   if( strstr( "hash function", value ) != NULL ) engine = hash_function;
   if( strstr( "hmac function", value ) != NULL ) engine = hmac_function;
   if( strstr( "sign", value ) != NULL ) engine = sign_function;

   if( engine != undefined_engine ) {
     oid = ak_oid_find_by_engine( engine );
     while( oid != NULL ) {
       exitcode = aktool_test_speed_oid( ++fc, oid );
       oid = ak_oid_findnext_by_engine( oid, engine );
     }
   }

  if( exitcode == EXIT_FAILURE )
    aktool_error(_("the string \"%s\" is unsupportable name of crypto engine, sorry ... "), value );
  return exitcode;

  return EXIT_FAILURE;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_test_speed_oid( int index, ak_oid oid )
{
  int exit_status = EXIT_FAILURE;

  switch( oid->engine ) {
    case block_cipher:
      switch( oid->mode ) {
         case algorithm:
         case encrypt_mode:
         case encrypt2k_mode:
         case acpkm:
         case mac:
         case aead:
           exit_status = aktool_test_speed_block_cipher( index, oid );
           break;
         default:
           aktool_error(_("used unsupported block cipher mode %s (%s)"), oid->name[0],
                                                          ak_libakrypt_get_mode_name( oid->mode ));
      }
      break;

      case hash_function:
        exit_status = aktool_test_speed_hash_function( index, oid );
      break;

      case hmac_function:
        exit_status = aktool_test_speed_hmac_function( index, oid );
      break;

      case sign_function:
        exit_status = aktool_test_speed_sign_function( index, oid );
      break;

    default:
      aktool_error(_("testing of identifier %s (%s) is unsupported now, sorry ... "),
                                                                        oid->name[0], oid->id[0] );
  }

  return exit_status;
}

/* ----------------------------------------------------------------------------------------------- */
 static ak_uint8 iv[48] = {
    0x12, 0x01, 0xf0, 0xe5, 0xd4, 0xc3, 0xb2, 0xa1, 0xf0, 0xce, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12,
    0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x90, 0x89, 0x78, 0x67, 0x56, 0x45, 0x34, 0x23,
    0xe9, 0xa8, 0x11, 0x12, 0x4c, 0x1b, 0x01, 0x1f, 0xf0, 0x87, 0xac, 0xab, 0x53, 0x19, 0x7d, 0xd1
  };

/* ----------------------------------------------------------------------------------------------- */
 const char *large  =  "   - large data encryption:";
 const char *packets = "   - packets encryption:";

/* ----------------------------------------------------------------------------------------------- */
 int aktool_test_speed_block_cipher( int index, ak_oid oid )
{
  clock_t timea = 1;
  double iter = 0, avg = 0;
  int error = ak_error_ok;
  size_t size = 0, sum = 0, isum = 0, secbytes = 0;
  int exit_status = EXIT_FAILURE;
  ak_pointer encryptionKey = NULL, authenticationKey = NULL;
  const size_t pcount = 2000; /* количество пакетов для тестирования */
  ak_uint8 *packet, out[1500], icode[128];

  size_t *lens = NULL;
 /* в режиме ecb все длины должны делиться на длину блока, т.е. 16 */
  size_t blens[12] = { 64, 128, 256, 384, 512, 640, 768, 832, 1024, 1040, 1280, 1488 };
 /* в остальных режимах допускаются произвольные размеры */
  size_t rlens[12] = { 72, 103, 128, 253, 460, 512, 731, 860, 1024, 1025, 1280, 1500 };

 /* 1. Создаем ключи */
  if(( encryptionKey = ak_oid_new_object( oid )) == NULL ) {
    aktool_error( _("incorrect creation of encryption key (code: %d)" ), ak_error_get_value( ));
    return exit_status;
  }
  if(( error = oid->func.first.set_key( encryptionKey, iv+16, 32 )) != ak_error_ok ) {
    aktool_error( _("incorrect assigning encryption key value (code: %d)" ), error );
    goto exit;
  }

  switch( oid->mode ) {
    case encrypt2k_mode: /* схемы с двумя ключами */
    case aead:

      if(( authenticationKey = ak_oid_new_second_object( oid )) == NULL ) {
        aktool_error( _("incorrect creation of authentication key (code: %d)" ),
                                                                            ak_error_get_value( ));
        goto exit;
      }
      if(( error = oid->func.second.set_key( authenticationKey, iv, 32 )) != ak_error_ok ) {
        aktool_error( _("incorrect assigning authentication key value (code: %d)" ), error );
        goto exit;
      }
      break;
    default: break;
  }

 /* 1. выполняем тестирование больших данных */
  printf("%3d. %s, %s\n", index, oid->name[0],
         ( oid->mode == algorithm ) ? _("ecb mode") : _( ak_libakrypt_get_mode_name( oid->mode )));
  if( large_array_test ) {
    for( ak_uint32 i = min_length_mb; i <= max_length_mb; i += 8 ) {
       ak_uint8 *data = malloc( size = ( size_t ) i*1024*1024 );
       memset( data, (ak_uint8)i+13, size );

     /* на очень больших объемах одного ключа мало, надо увеличивать ресурс */
     /* далее - не очень хороший стиль, мы пользуемся тем,
        что все ключевые структуры содержат ключ первым элементом структуры */
       ((ak_skey)encryptionKey)->resource.value.counter = size;
       if( authenticationKey != NULL )
         ((ak_skey)authenticationKey)->resource.value.counter = size;

     /* выводим информацию */
       if( !ki.quiet ) { printf(_("%s %3d Mb%s"), _(large), i, "\r" ); fflush( stdout ); }

     /* выполняем алгоритм */
       switch( oid->mode ) {
          case algorithm:
            timea = clock();
            error = ak_bckey_encrypt_ecb( encryptionKey, data, data, size );
            timea = clock() - timea;
          break;

          case encrypt_mode: /* базовый режим с одним ключом и синхропосылкой */
            timea = clock();
            error = oid->func.direct(
               encryptionKey,     /* ключ шифрования */
               data,              /* указатель на зашифровываемые данные */
               data,              /* указатель на зашифрованные данные */
               size,              /* размер шифруемых данных */
               iv,                /* синхропосылка для режима шифрования */
               sizeof( iv )       /* доступный размер синхропосылки */
            );
            timea = clock() - timea;
          break;

          case mac: /* имитовставка */
             timea = clock();
             error = oid->func.direct(
               encryptionKey,     /* ключ шифрования */
               data,              /* указатель на данные для которых вычисляется имитовставка */
               size,              /* размер данных */
               icode,             /* имитовставка */
               sizeof( icode )    /* доступный размер памяти для имитовставки */
             );
             timea = clock() - timea;
          break;

          case acpkm:
           /* определяем максимальный размер секции */
            if( ((ak_bckey)encryptionKey)->bsize == 8 )
              secbytes = 8*ak_libakrypt_get_option_by_name( "acpkm_section_magma_block_count" );
             else secbytes = 16*ak_libakrypt_get_option_by_name( "acpkm_section_kuznechik_block_count" );

            timea = clock();
            error = oid->func.direct(
              encryptionKey,     /* ключ шифрования */
              data,              /* указатель на зашифровываемые данные */
              data,              /* указатель на зашифрованные данные */
              size,              /* размер шифруемых данных */
              secbytes,          /* размер одной секции в байтах */
              iv,                /* синхропосылка для режима гаммирования */
              sizeof( iv )       /* доступный размер синхропосылки */
            );
            timea = clock() - timea;
          break;

          case encrypt2k_mode: /* шифрование с двумя ключами */
            timea = clock();
            error = oid->func.direct(
              encryptionKey,     /* ключ шифрования */
              authenticationKey, /* ключ имитозащиты */
              data,              /* указатель на зашифровываемые данные */
              data,              /* указатель на зашифрованные данные */
              size,              /* размер шифруемых данных */
              iv,                /* синхропосылка для режима гаммирования */
              sizeof( iv )       /* доступный размер синхропосылки */
            );
            timea = clock() - timea;
          break;

          case aead: /* двухключевое шифрование и имитозащита */
            timea = clock();
            error = oid->func.direct(
              encryptionKey,     /* ключ шифрования */
              authenticationKey, /* ключ имитозащиты */
              data,              /* ассоциированные данные */
              128,               /* размер ассоциированных данных */
              data+128,          /* указатель на зашифровываемые данные */
              data+128,          /* указатель на зашифрованные данные */
              size-128,          /* размер шифруемых данных */
              iv,                /* синхропосылка для режима гаммирования */
              sizeof( iv ),      /* доступный размер синхропосылки */
              icode,             /* имитовставка */
              sizeof( icode )    /* доступный размер памяти для имитовставки */
            );
            timea = clock() - timea;
          break;

          default:
            error = ak_error_undefined_function;
            printf(_("%3d: block cipher %s, %s\n"), index, oid->name[0],
                                                          ak_libakrypt_get_mode_name( oid->mode ));
       }
       if( error != ak_error_ok ) {
         aktool_error(_("computational error (%d)"), error );
         free(data);
         goto exit;
       }
       if( !ki.quiet ) {
         if( ki.verbose ) {
           printf(_("%s %3d Mb, time: %8f sec., per 1Mb: %f sec., average: %f MBs\n"),
            _(large),
            i,
            (double) timea / (double) CLOCKS_PER_SEC,
            (double) timea / ((double) CLOCKS_PER_SEC*i),
            (double) CLOCKS_PER_SEC*i / (double) timea );
         }
          else printf(_("%s %3d Mb, time: %8f sec.%s"),
                                     _(large), i, (double) timea / (double) CLOCKS_PER_SEC, "\r" );
       }

       iter += 1;
       avg += (double) CLOCKS_PER_SEC*i / (double) timea;
       free(data);
    }
    if( !ki.quiet )
      printf(_("   - average speed: %10f MBs.                              \n"), avg/iter );
  } /* конец large_array_test */


 /* 2. выполняем тестирование пакетных данных */
  if( packets_test ) {
    switch( oid->mode ) {
      case algorithm:
        lens = blens;
        break;

      default:
        lens = rlens;
        break;
    }

    sum = isum = 0;
    packet = malloc( 1500*(pcount+10) );
    for( size_t i = 0; i < 1500*(pcount+10); i++ ) packet[i] = (ak_uint8)((1+i)*(i+2));

    size_t epacketlen = 0;
    size_t rlen = sizeof(rlens)/sizeof( size_t);
    size_t headlen = 8;

    for( size_t j = 0; j < rlen; j++ ) {
       printf("%s %s", _(packets), "\r" ); fflush( stdout );

       size = 0;
       ((ak_skey)encryptionKey)->resource.value.counter = pcount*1500;
       if( authenticationKey != NULL )
         ((ak_skey)authenticationKey)->resource.value.counter = pcount*1500;

     /* выполняем алгоритм */
       switch( oid->mode ) {
          case algorithm:
            timea = clock();
            for( size_t i = 0; i < pcount; i++, size += lens[j] ) {
              ak_bckey_encrypt_ecb( encryptionKey, packet+size, out, lens[j] );
            }
            timea = clock() - timea;
          break;

          case encrypt_mode: /* базовый режим с одним ключом и синхропосылкой */
            timea = clock();
            for( size_t i = 0; i < pcount; i++, size += lens[j] ) {
               error = oid->func.direct(
                 encryptionKey,     /* ключ шифрования */
                 packet+size,       /* указатель на зашифровываемые данные */
                 out,               /* указатель на зашифрованные данные */
                 lens[j],           /* размер шифруемых данных */
                 iv,                /* синхропосылка для режима шифрования */
                 sizeof( iv )       /* доступный размер синхропосылки */
               );
            }
            timea = clock() - timea;
          break;

          case mac: /* имитовставка */
            timea = clock();
            for( size_t i = 0; i < pcount; i++, size += lens[j] ) {
               error = oid->func.direct(
                 encryptionKey,     /* ключ шифрования */
                 packet+size,       /* указатель на данные для которых вычисляется имитовставка */
                 lens[j],           /* размер данных */
                 icode,             /* имитовставка */
                 sizeof( icode )    /* доступный размер памяти для имитовставки */
               );
            }
            timea = clock() - timea;
          break;

          case acpkm:
           /* определяем максимальный размер секции */
            if( ((ak_bckey)encryptionKey)->bsize == 8 )
              secbytes = 8*ak_libakrypt_get_option_by_name( "acpkm_section_magma_block_count" );
             else secbytes = 16*ak_libakrypt_get_option_by_name( "acpkm_section_kuznechik_block_count" );

            timea = clock();
            for( size_t i = 0; i < pcount; i++, size += lens[j] ) {
               error = oid->func.direct(
                 encryptionKey,     /* ключ шифрования */
                 packet+size,              /* указатель на зашифровываемые данные */
                 out,            /* указатель на зашифрованные данные */
                 lens[j],              /* размер шифруемых данных */
                 secbytes,          /* размер одной секции в байтах */
                 iv,                /* синхропосылка для режима гаммирования */
                 sizeof( iv )       /* доступный размер синхропосылки */
               );
            }
            timea = clock() - timea;
          break;

          case encrypt2k_mode: /* шифрование с двумя ключами */
            timea = clock();
            for( size_t i = 0; i < pcount; i++, size += lens[j] ) {
               error = oid->func.direct(
                 encryptionKey,     /* ключ шифрования */
                 authenticationKey, /* ключ имитозащиты */
                 packet+size,       /* указатель на зашифровываемые данные */
                 out,               /* указатель на зашифрованные данные */
                 lens[j],           /* размер шифруемых данных */
                 iv,                /* синхропосылка для режима гаммирования */
                 sizeof( iv )       /* доступный размер синхропосылки */
               );
            }
            timea = clock() - timea;
          break;

          case aead: /* двухключевое шифрование и имитозащита */
            timea = clock();
            for( size_t i = 0; i < pcount; i++, size += lens[j] ) {
               error = oid->func.direct(
                 encryptionKey,       /* ключ шифрования */
                 authenticationKey,   /* ключ имитозащиты */
                 packet+size,         /* ассоциированные данные */
                 headlen,             /* размер ассоциированных данных */
                 packet+size+headlen, /* указатель на зашифровываемые данные */
                 out,                 /* указатель на зашифрованные данные */
                 lens[j]-headlen,     /* размер шифруемых данных */
                 iv,                  /* синхропосылка для режима гаммирования */
                 sizeof( iv ),        /* доступный размер синхропосылки */
                 icode,               /* имитовставка */
                 sizeof( icode )      /* доступный размер памяти для имитовставки */
               );
            }
            timea = clock() - timea;
          break;

          default:
          break;
       }
       if( error != ak_error_ok ) aktool_error(_("incorrect incryption"));

       double sec = (double) timea / (double) CLOCKS_PER_SEC;
       size_t persec = (size_t) ((double)pcount / sec );

       if( !ki.quiet ) {
         if( ki.verbose )
           printf(_("%s %4lu bytes, time: %f sec., packet per sec.: %lu\n"),
                         _(packets), (unsigned long int)lens[j], sec, (unsigned long int)persec );
          else printf(_("%s %4lu bytes, time: %f sec., packet per sec.: %7lu%s"),
                   _(packets), (unsigned long int)lens[j], sec, (unsigned long int)persec, "\r" );
         fflush( stdout );
       }
       sum += persec;
       isum += ( lens[j]*persec );
       epacketlen += lens[j];
    }
    free( packet );
    if( !ki.quiet ) {
      printf(_("   - average packets:                                                              \n"
      "\t - %6lu per sec. (mean value)\n\t - %6lu per sec. (integral value)\n"),
                               (unsigned long int)(sum/12), (unsigned long int)(isum/epacketlen ));
    }
  }

  exit_status = EXIT_SUCCESS;
  exit:
   ak_oid_delete_object( oid, encryptionKey );

 return exit_status;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_test_speed_hash_function( int index, ak_oid oid )
{
  size_t size = 0;
  clock_t timea = 1;
  double iter = 0, avg = 0;
  ak_uint8 *data, icode[64];
  int error = ak_error_ok, exit_status = EXIT_FAILURE;
  ak_pointer ctx;

  if( oid->mode != algorithm ) {
    printf(_("hash function's mode \"%s\" is not supported yet for testing, sorry ... \n"),
                                                           ak_libakrypt_get_mode_name( oid->mode ));
    return EXIT_SUCCESS;
  }

  if(( ctx = ak_oid_new_object( oid )) == NULL ) {
    aktool_error( _("incorrect creation of hash function context (code: %d)" ), ak_error_get_value());
    return exit_status;
  }

  printf(_("%3d. [%s:"), index, oid->name[0] );
  if( !ki.verbose ) printf(_(" %uMB "), min_length_mb );
   else printf("\n");
  fflush( stdout );

 /* теперь собственно тестирование скорости реализации */
  for( ak_uint32 i = min_length_mb; i <= max_length_mb; i += 8 ) {
    data = malloc( size = ( size_t ) i*1024*1024 );
    memset( data, (ak_uint8)i+13, size );

    timea = clock();
    error = ak_hash_ptr( ctx, data, size, icode, sizeof( icode ));
    timea = clock() - timea;

    free( data );
    if( error != ak_error_ok ) {
      aktool_error(_("computational error (%d)"), error );
      goto exit;
    }
    if( ki.verbose )
      printf(_(" %3uMB: %s time = %fs, per 1MB = %fs, speed = %f MBs\n"), (unsigned int)i,
               oid->name[0],
               (double) timea / (double) CLOCKS_PER_SEC,
               (double) timea / ( (double) CLOCKS_PER_SEC*i ),
               (double) CLOCKS_PER_SEC*i / (double) timea );
     else { printf("."); fflush( stdout ); }

     iter += 1;
     avg += (double) CLOCKS_PER_SEC*i / (double) timea;
  }
  if( !ki.verbose ) printf(_(" %uMB"), max_length_mb );
  printf(_("], average speed: %10f MBs\n"), avg/iter );

  exit_status = EXIT_SUCCESS;
  exit:
   ak_oid_delete_object( oid, ctx );

 return exit_status;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_test_speed_hmac_function( int index, ak_oid oid )
{
  size_t size = 0;
  clock_t timea = 1;
  double iter = 0, avg = 0;
  ak_uint8 *data, icode[64];
  int error = ak_error_ok, exit_status = EXIT_FAILURE;
  ak_pointer authenticationKey = NULL;

  if( oid->mode != algorithm ) {
    printf(_("hmac function's mode \"%s\" is not supported yet for testing, sorry ... \n"),
                                                           ak_libakrypt_get_mode_name( oid->mode ));
    return EXIT_SUCCESS;
  }

 /* 1. Создаем ключи */
  if(( authenticationKey = ak_oid_new_object( oid )) == NULL ) {
    aktool_error( _("incorrect creation of authentication key (code: %d)" ), ak_error_get_value( ));
    return exit_status;
  }
  if(( error = oid->func.first.set_key( authenticationKey, iv, 32 )) != ak_error_ok ) {
    aktool_error( _("incorrect assigning authentication key value (code: %d)" ), error );
    goto exit;
  }

  printf(_("%3d. [%s:"), index, oid->name[0] );
  if( !ki.verbose ) printf(_(" %uMB "), min_length_mb );
   else printf("\n");
  fflush( stdout );

 /* теперь собственно тестирование скорости реализации */
  for( ak_uint32 i = min_length_mb; i <= max_length_mb; i += 8 ) {
    data = malloc( size = ( size_t ) i*1024*1024 );
    memset( data, (ak_uint8)i+13, size );

    timea = clock();
    error = ak_hmac_ptr( authenticationKey, data, size, icode, sizeof( icode ));
    timea = clock() - timea;

    free( data );
    if( error != ak_error_ok ) {
      aktool_error(_("computational error (%d)"), error );
      goto exit;
    }
    if( ki.verbose )
      printf(_(" %3uMB: %s time = %fs, per 1MB = %fs, speed = %f MBs\n"), (unsigned int)i,
               oid->name[0],
               (double) timea / (double) CLOCKS_PER_SEC,
               (double) timea / ( (double) CLOCKS_PER_SEC*i ),
               (double) CLOCKS_PER_SEC*i / (double) timea );
     else { printf("."); fflush( stdout ); }

     iter += 1;
     avg += (double) CLOCKS_PER_SEC*i / (double) timea;
  }
  if( !ki.verbose ) printf(_(" %uMB"), max_length_mb );
  printf(_("], average speed: %10f MBs\n"), avg/iter );

  exit_status = EXIT_SUCCESS;
  exit:
   ak_oid_delete_object( oid, authenticationKey );

 return exit_status;
}

/* ----------------------------------------------------------------------------------------------- */
 static int aktool_test_sign_function_for_one_curve( ak_signkey ctx, ak_oid curve )
{
  clock_t timea = 1;
  ak_uint8 *out[64];
  struct random generator;
  size_t j, i = 0, cnt = 0;
  double iter = 0, avg = 0, val = 0;
  ak_uint64 e[8], k[8];

  if( ak_random_create_lcg( &generator ) != ak_error_ok ) return EXIT_FAILURE;

  printf(_("curve: %s (%s) "), curve->name[0], curve->id[0] );
  if( ki.verbose ) printf("\n");

  for( j = 1; j < 9; j++ ) {
     i = cnt = j*250;
     ak_random_ptr( &generator, e, 64 );
     ak_random_ptr( &generator, k, 64 );

     timea = clock();
     while( i ) {
        ak_signkey_sign_const_values( ctx, k, e, out );
        i--;
     }
     timea = clock() - timea;
     val = (cnt *(double) CLOCKS_PER_SEC )/(double) timea;
     if( ki.verbose ) {
       printf(_("[count: %3lu, time = %fs, speed: %f sec., count: %f]\n"),
       (long unsigned int)cnt,
       (double) timea / (double) CLOCKS_PER_SEC,
       (double) timea / (cnt *(double) CLOCKS_PER_SEC ),
       val );
     } else { printf("."); fflush( stdout ); }

     if( j > 1 ) { iter += 1; avg += val; }
  }
  printf(_(" average speed: %10f sgn/sec.\n"), avg/iter );
  ak_random_destroy( &generator );

 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_test_speed_sign_function( int index, ak_oid oid )
{
  int exit_status = EXIT_FAILURE;
  ak_oid curve = NULL;
  ak_signkey ctx = NULL;
  struct random generator;

  (void) index;
  if( oid->mode != algorithm ) {
    printf(_("using unsupported mode %s"), ak_libakrypt_get_mode_name( oid->mode ));
    return EXIT_SUCCESS;
  }

  if( ak_random_create_lcg( &generator ) != ak_error_ok ) return EXIT_FAILURE;
  if(( ctx = ak_oid_new_object( oid )) == NULL ) {
    aktool_error( "incorrect creation of secret key context");
    return EXIT_FAILURE;
  }

 /* первый тест - скорость вычислений, без учета генерации */
  curve = ak_oid_find_by_mode( wcurve_params );
  while( curve != NULL ) {
    ak_wcurve wc = ( ak_wcurve )curve->data;
    if(( ctx->ctx.data.sctx.hsize >> 3 ) == wc->size ) {
      ak_signkey_set_curve( ctx, wc );
      ak_signkey_set_key_random( ctx, &generator );
      /* здесь начинаем тестирование */
      if(( exit_status =
               aktool_test_sign_function_for_one_curve( ctx, curve )) == EXIT_FAILURE ) goto labex;
    }
    curve = ak_oid_findnext_by_mode( curve, wcurve_params );
  }

  labex:
    ak_random_destroy( &generator );
    ak_oid_delete_object( oid, ctx );
 return exit_status;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                  aktool_test.c  */
/* ----------------------------------------------------------------------------------------------- */
