/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2024 by Axel Kenzo, axelkenzo@mail.ru                                            */
/*                                                                                                 */
/*  Прикладной модуль, реализующий процедуры вычисления сохранения контрольных сумм                */
/*                                                                                                 */
/*  aktool_icode_evaluate.c                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 #include "aktool.h"
 #include <libakrypt.h>
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
    if( ki->method->engine == hash_function ) ak_oid_delete_object( ki->method, ki->handle );
     else
      ak_skey_delete( ki->handle );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*                      функция выработки производного ключа                                       */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer aktool_icode_get_derived_key( const char *value, aktool_ki_t *ki, ak_file fp )
{
    struct file infp;
    ak_pointer dkey = NULL;
    size_t total_size = 0, blocks = 0;

   /* проверяем надо ли делать производный ключ */
    if(( ki->method->engine == hash_function ) || ( ki->key_derive == ak_false ))
      return ki->handle;
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
        if( koid->engine != block_cipher ) return dkey;
    }

   /* если снаружи ни чего не открыто, то делаем это самостоятельно */
    if( fp != NULL ) total_size = fp->size;
      else {
             if( ak_file_open_to_read( &infp, value ) == ak_error_ok ) {
               total_size = infp.size;
               ak_file_close( &infp );
             }
              else return dkey;
      }

   /* в заключение, подправляем ресурс ключа алгоритма блочного шифрования
      иначе придется вырабатывать следующий производный ключ и т.д. */
    if(( blocks = ( total_size / ki->size )) > ((ak_skey)dkey)->resource.value.counter ) {
      ((ak_skey)dkey)->resource.value.counter = blocks;
      if( ak_log_get_level() > ak_log_standard ) {
         ak_error_message_fmt( ak_error_ok, __func__,
                _("the resource of the derived key was increased up to %llu blocks (file %s)"),
                                       (ak_uint64)((ak_skey)dkey)->resource.value.counter, value );
      }
    }

  return dkey;
}

/* ----------------------------------------------------------------------------------------------- */
/*                     функции вычисления контрольных сумм                                         */
/* ----------------------------------------------------------------------------------------------- */
#ifdef AK_HAVE_GELF_H
 static int aktool_icode_evaluate_gelf( const char *value, aktool_ki_t *ki )
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
     /* формируем виртуальное имя файла - ключ доступа в виртуальной таблице */
      ak_snprintf( segment_value, sizeof( segment_value ) -1, "%s/%08jx", value, phdr.p_offset );
     /* при необходимости, формируем производный ключ */
      if(( dkey = aktool_icode_get_derived_key( segment_value, ki, &fp )) == NULL ) {
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
        if(( !ki->quiet ) && ( !ki->dont_show_icode))
          aktool_icode_out( stdout, segment_value, ki, icode, ki->size +8 );
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
 static int aktool_icode_evaluate_function( const char *value, ak_pointer ptr )
{
    ak_uint8 icode[256];
    aktool_ki_t *ki = ptr;
    ak_pointer dkey = NULL;
    int error = ak_error_ok;

   /* проверяем черный список */
    if( ak_htable_get_str( &ki->exclude_file, value, NULL ) != NULL ) return ak_error_ok;

   /* статистика */
    ki->statistical_data.total_files++;

   /* проверяем, что надо контролировать целостность всего файла */
    if( !ki->only_segments ) {
     /* вычисляем производный ключ */
      if(( dkey = aktool_icode_get_derived_key( value, ki, NULL )) == NULL ) {
        ki->statistical_data.skiped_files++;
        return ak_error_null_pointer;
      }
     /* вычисляем контрольную сумму от заданного файла и помещаем ее в таблицу */
      error = ki->icode_file( dkey, value, icode, ki->size );
      if( dkey != ki->handle ) ak_skey_delete( dkey );
     /* проверка результата и его сохнение в хеш-таблице */
      if( error == ak_error_ok ) {
        ki->statistical_data.hashed_files++;
        if(( !ki->quiet ) && ( !ki->dont_show_icode))
          aktool_icode_out( stdout, value, ki, icode, ki->size );
        ak_htable_add_str_value( &ki->icodes, value, icode, ki->size );
      }
       else {
         ki->statistical_data.skiped_files++;
         goto labexit;
      }
    } /* if(only_segments) */

   /* теперь приступаем к разбору исполняемых файлов */
  #ifdef AK_HAVE_GELF_H
   if( !ki->ignore_segments ) error = aktool_icode_evaluate_gelf( value, ki );
  #endif

   labexit:
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция вычисляет контрольные суммы по заданным спискам каталогов и файлов */
 int aktool_icode_evaluate( aktool_ki_t *ki )
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
          aktool_icode_evaluate_function(( char * )ki->include_file.current->data, ki );
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
          ak_file_find( value, ki->pattern, aktool_icode_evaluate_function, ki, ki->tree );
      } while( ak_list_next( &ki->include_path ));
    }

   /* финальное сообщение об ошибках */
    if( ki->statistical_data.skiped_files ) {
      exit_status = EXIT_FAILURE;
      aktool_error(_("aktool found %d error(s), try aktool with \"--audit-file stderr --audit 2\""
                           " options or see syslog messages"), ki->statistical_data.skiped_files );
    }

   /* вывод статистики */
    if( !ki->quiet ) {
      if(( !ki->dont_show_icode ) && ( !ki->dont_show_stat )) printf("\n");
      if( !ki->dont_show_stat ) {
        printf(_("the total number of files found: %llu, of which:\n"),
                                       (long long unsigned int) ki->statistical_data.total_files );
        printf(_(" %6llu have been discarded\n"),
                                      (long long unsigned int) ki->statistical_data.skiped_files );
        printf(_(" %6llu have been proceed\n"),
                                      (long long unsigned int) ki->statistical_data.hashed_files );
       #ifdef AK_HAVE_GELF_H
        if( !ki->ignore_segments ) {
          printf(_(" %6llu contain downloadable segments\n"),
                                       (long long unsigned int) ki->statistical_data.executables );
          if( ki->statistical_data.skipped_executables )
            printf(_(" %6llu downloadable segments discarded\n"),
                               (long long unsigned int) ki->statistical_data.skipped_executables );
        }
       #endif
      }
    }

   aktool_icode_destroy_handle( ki );

  return exit_status;
}

/* ----------------------------------------------------------------------------------------------- */
/*                           функции проверки контрольных сумм                                     */
/* ----------------------------------------------------------------------------------------------- */
 static int aktool_icode_check_function( const char *value, ak_pointer ptr )
{
    ak_uint8 icode[256];
    ak_pointer dkey = NULL;
    ak_uint8 *iptr = (ak_uint8 *)ptr;
    int error = ak_error_ok;

   /* статистика */
    ki.statistical_data.total_files++;

   /* вычисляем производный ключ */
    if(( dkey = aktool_icode_get_derived_key( value, &ki, NULL )) == NULL ) {
      ki.statistical_data.skiped_files++;
      return ak_error_get_value();
    }

   /* вычисляем контрольную сумму от заданного файла и помещаем ее в таблицу */
    error = ki.icode_file( dkey, value, icode, ki.size );
    if( dkey != ki.handle ) ak_skey_delete( dkey );

    if( error != ak_error_ok ) {
      ak_error_message_fmt( error, __func__, _("%s is lost"), value );
      if( !ki.quiet ) aktool_error(_("%s is lost"), value );
      ki.statistical_data.skiped_files++;
      ki.statistical_data.deleted_files++;
      return error;
    }

   /* сравниваем значения */
    if( memcmp( icode, iptr, ki.size ) != 0 ) {
      ak_error_message_fmt( ak_error_not_equal_data, __func__, _("%s has been modified"), value );
      if( !ki.quiet ) aktool_error(_("%s has been modified"), value );
      ki.statistical_data.skiped_files++;
      ki.statistical_data.changed_files++;
      return ak_error_not_equal_data;
    }
     else ki.statistical_data.hashed_files++;

   /* пытемся вывести результат в консоль */
    if(( !ki.quiet ) && ( !ki.dont_show_icode )) {
      printf("%s %s Ok\n", value, ak_ptr_to_hexstr( iptr,  ki.size, ak_false ));
    }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_icode_check_from_database( aktool_ki_t *ki )
{
    size_t i = 0;
    int exit_status = EXIT_FAILURE;

   /* основной цикл */
    for( i = 0; i < ki->icodes.count; i++ ) {
      ak_list list = &ki->icodes.list[i];
      if( list->count == 0 ) continue;
      ak_list_first( list );
      do{
         ak_keypair kp = (ak_keypair)list->current->data;

        /* проверки  */
         if( kp->data == NULL ) {
           ak_error_message( ak_error_null_pointer, __func__, _("using null pointer to keypair"));
           return EXIT_FAILURE;
         }

        /* проверяем соотвествие длин */
         if( ki->size != kp->value_length ) {
           if( ki->size +8 == kp->value_length ) continue;
            else {
              /* расхождение в длинах имитовставок */
               ki->statistical_data.total_files++;
               ki->statistical_data.skiped_files++;
               ak_error_message_fmt( ak_error_not_equal_data, __func__,
                                  _("unexpected length of integrity code for %s file"), kp->data );
               continue;
            }
         }

        /* выполняем проверку конкретного файла */
         aktool_icode_check_function( (const char *)kp->data, kp->data +kp->key_length );
      }
       while( ak_list_next( list ));
    }

   /* финальное предупреждение */
    if( ki->statistical_data.skiped_files ) {
      aktool_error(_("aktool found %d error(s), try aktool with \"--audit-file stderr --audit 2\""
                           " options or see syslog messages"), ki->statistical_data.skiped_files );
      exit_status = EXIT_FAILURE;
    }
     else exit_status = EXIT_SUCCESS;

   /* вывод статистики о проделанной работе */
    if( !ki->quiet ) {
      if( !ki->dont_show_stat ) {
        if(( !ki->dont_show_icode ) || ( ki->statistical_data.skiped_files )) printf("\n");
        printf(_("the total number of files checked: %llu, of which:\n"),
                                       (long long unsigned int) ki->statistical_data.total_files );
        printf(_(" %6llu have been proceed\n"),
                                      (long long unsigned int) ki->statistical_data.hashed_files );
        printf(_(" %6llu have been discarded\n"),
                                      (long long unsigned int) ki->statistical_data.skiped_files );
        if( ki->statistical_data.skiped_files ) {
          printf(_(" %6llu have been deleted\n"),
                                     (long long unsigned int) ki->statistical_data.deleted_files );
          printf(_(" %6llu have been changed\n"),
                                     (long long unsigned int) ki->statistical_data.changed_files );
        }
      }
    }

 return exit_status;
}

/* ----------------------------------------------------------------------------------------------- */
 static int aktool_icode_check_file_function( const char *value, ak_pointer ptr )
{
    ak_keypair kp = NULL;
    aktool_ki_t *ki = ptr;
    int error = ak_error_ok;

   /* проверяем черный список */
    if( ak_htable_get_str( &ki->exclude_file, value, NULL ) != NULL ) return ak_error_ok;

   /* ищем файл в базе */
    if(( kp = ak_htable_exclude_keypair_str( &ki->icodes, value )) == NULL ) {
      ki->statistical_data.total_files++;
      ki->statistical_data.new_files++;
      if( !ki->quiet ) aktool_error( _("%s is a new file"), value );
      return ak_error_message_fmt( ak_error_htable_key_not_found, __func__,
                                                                    _("%s is a new file"), value );
    }

   /* проверяем, что база корректна */
    if( kp->data == NULL ) {
      ak_error_message( ak_error_null_pointer, __func__, _("using null pointer to keypair"));
      goto labex;
    }

   /* выполняем проверку конкретного файла */
    error = aktool_icode_check_function( (const char *)kp->data, kp->data +kp->key_length );

  labex:
    if( kp != NULL ) ak_keypair_delete( kp );
    return error;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_icode_check_from_directory( aktool_ki_t *ki )
{
    size_t total_errors = 0;
    int exit_status = EXIT_FAILURE;

   /* обнуляем счетчики */
    memset( &ki->statistical_data, 0, sizeof( struct icode_stat ));

   /* создаем контекст алгоритма хеширования или имитозащиты */
    if( aktool_icode_create_handle( ki ) != ak_error_ok ) return EXIT_FAILURE;

   /* начинаем с обхода файлов */
    if( ki->include_file.count ) {
      ak_list_first( &ki->include_file );
      do{
          aktool_icode_check_file_function( ( char * )ki->include_file.current->data, ki );
      } while( ak_list_next( &ki->include_file ));
    }

   /* теперь продолжаем обходом каталогов */
    if( ki->include_path.count ) {
      ak_list_first( &ki->include_path );
      do{
          const char *value = ( const char * )ki->include_path.current->data;
         /* удаляем, при необходимости, обратный слэш */
          if( strlen(value) > 1 ) {
            size_t vlen = strlen( value );
            if( value[vlen -1] == '/' ) ((char *)ki->include_path.current->data)[vlen-1] = 0;
          }
         /* проверяем черный список */
          if( ak_htable_get_str( &ki->exclude_path, value, NULL ) != NULL ) continue;
         /* запускаем вычисление контрольной суммы */
          ak_file_find( value, ki->pattern, aktool_icode_check_file_function, ki, ki->tree );
      } while( ak_list_next( &ki->include_path ));

     /* осталось найти то, что осталось непроверенным */
      for( size_t i = 0; i < ki->icodes.count; i++ ) {
         ak_list list = &ki->icodes.list[i];
         if( list->count == 0 ) continue;
         ak_list_first( list );
         do{
            ak_keypair kp = (ak_keypair)list->current->data;
            // printf("    - [key: %s, val: %s]\n", kp->data,
            //   ak_ptr_to_hexstr( kp->data + kp->key_length,  kp->value_length, ak_false ));

            if( kp->value_length == ki->size ) {
            /**/
              ki->statistical_data.total_files++;
              ki->statistical_data.deleted_files++;
              aktool_error(_("%s has been deleted"), kp->data );
              ak_error_message_fmt( ak_error_file_exists, __func__, _("%s has been deleted"), kp->data );
            }
         } while( ak_list_next( list ));
      }
    } /* if( include_path ) */

   /* финальное сообщение об ошибках */
    total_errors = ki->statistical_data.skiped_files +
                               ki->statistical_data.deleted_files + ki->statistical_data.new_files;
    if( total_errors ) {
      exit_status = EXIT_FAILURE;
      aktool_error(_("aktool found %d error(s), try aktool with \"--audit-file stderr --audit 2\""
                                                " options or see syslog messages"), total_errors );
    }
     else exit_status = EXIT_SUCCESS;

   /* вывод статистики о проделанной работе */
    if( !ki->quiet ) {
      if( !ki->dont_show_stat ) {
        if(( !ki->dont_show_icode ) || ( ki->statistical_data.skiped_files )) printf("\n");
        printf(_("the total number of files checked: %llu, of which:\n"),
                                       (long long unsigned int) ki->statistical_data.total_files );
       /* успешно проверены */
        printf(_(" %6llu have been proceed\n"),
                                      (long long unsigned int) ki->statistical_data.hashed_files );
       /* проверка завершилась с ошибкой */
        if( ki->statistical_data.deleted_files )
          printf(_(" %6llu have been deleted\n"),
                                     (long long unsigned int) ki->statistical_data.deleted_files );
        if( ki->statistical_data.changed_files )
          printf(_(" %6llu have been changed\n"),
                                     (long long unsigned int) ki->statistical_data.changed_files );
        if( ki->statistical_data.new_files )
          printf(_(" %6llu new files found\n"),
                                         (long long unsigned int) ki->statistical_data.new_files );
      }
    }

   aktool_icode_destroy_handle( ki );

  return exit_status;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                        aktool_icode_evaluate.c  */
/* ----------------------------------------------------------------------------------------------- */
