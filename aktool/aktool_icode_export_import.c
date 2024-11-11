/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2024 by Axel Kenzo, axelkenzo@mail.ru                                            */
/*                                                                                                 */
/*  Прикладной модуль, реализующий процедуры чтения и сохранения контрольных сумм                  */
/*                                                                                                 */
/*  aktool_icode_export_import.c                                                                   */
/* ----------------------------------------------------------------------------------------------- */
 #include "aktool.h"
 #include <libakrypt.h>
#ifdef AK_HAVE_ERRNO_H
 #include <errno.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция выводит контрольную сумму в консоль */
 void aktool_icode_out( FILE *fp, const char *value,
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
/*! \brief Функция выводит все контрольные суммы в консоль */
 int aktool_icode_out_all( FILE *fp, aktool_ki_t *ki )
{
    size_t i = 0, cnt = 0;

   /* перебираем всю хеш-таблицу */
    for( i = 0; i < ki->icodes.count; i++ ) {
       ak_list list = &ki->icodes.list[i];
       cnt += list->count;
       if( list->count == 0 ) continue;
       ak_list_first( list );
       do{
         ak_keypair kp = (ak_keypair)list->current->data;
         if( !ki->quiet ) aktool_icode_out( fp, (const char *)kp->data,
                                                   ki, kp->data+kp->key_length, kp->value_length );
       } while( ak_list_next( list ));
    }

   /* выводим статистику  */
    if(( !ki->quiet ) && ( !ki->dont_show_stat )) {
      printf(_("the database contains %llu value(s)\n"), (long long unsigned int) cnt );
    }

 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция сохраняет хэш-таблицу с вычисленными контрольными суммами или имтовставками в
    заданный файл в формате, который указан пользователем                                          */
/* ----------------------------------------------------------------------------------------------- */
 int aktool_icode_export_checksum( aktool_ki_t *ki )
{
    size_t i = 0;
    FILE *fp = NULL;
    int exit_status = EXIT_FAILURE;

   /* провеяем, надо ли вообще что-то делать */
    if( ki->dont_save_database ) return EXIT_SUCCESS;

   /* определяемся с выводом в формате bsd */
    if( ki->tag ) ki->field = format_bsd;
    if( ki->field == format_bsd ) ki->tag = ak_true;

    switch( ki->field ) {
      case format_binary:
        if( ak_htable_export_to_file( &ki->icodes, ki->pubkey_file ) != ak_error_ok )
          aktool_error(_("incorrectly writing results to a file %s (%s)"),
                                                               ki->pubkey_file, strerror( errno ));
         else {
           exit_status = EXIT_SUCCESS;
         }
        break;

      default: /* выводим в текстовом формате */
        if(( fp = fopen( ki->pubkey_file, "w" )) == NULL ) {
          aktool_error(_("incorrect output checksum to file %s (%s)"),
                                                               ki->pubkey_file, strerror( errno ));
          break;
        }

        for( i = 0; i < ki->icodes.count; i++ ) {
           ak_list list = &ki->icodes.list[i];
           if( list->count == 0 ) continue;
           ak_list_first( list );
           do{
                ak_keypair kp = (ak_keypair)list->current->data;
                aktool_icode_out( fp, (const char *)kp->data,
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
/*                                          Функции импорта                                        */
/* ----------------------------------------------------------------------------------------------- */
 tchar* aktool_strtok_r( tchar *str, const tchar *delim, tchar **nextp)
{
 tchar *ret = NULL;

    if( str == NULL ) { str = *nextp; }

    str += strspn( str, delim );
    if (*str == '\0') { return NULL; }

    ret = str;
    str += strcspn( str, delim );

    if (*str) { *str++ = '\0'; }

    *nextp = str;
    return ret;
}

/* ----------------------------------------------------------------------------------------------- */
 static int aktool_icode_import_checksum_line( const char *string, ak_pointer ptr )
{
    aktool_ki_t *ki = (aktool_ki_t *)ptr;

    size_t len;
    ak_uint8 out2[256];
    tchar *substr = NULL, *filename = NULL, *icode = NULL;
    int error = ak_error_ok, reterror = ak_error_undefined_value;

   /* строку нашли - увеличиваем счетчик */
    ki->statistical_data.total_lines++;

   /* получаем первый токен */
    if(( icode = aktool_strtok_r( (tchar *)string, "(", &substr )) == NULL )
      return ak_error_undefined_value;

    if( strlen( substr ) == 0 ) { /* строка не содержит скобки => вариант строки в формате Linux */
     /* получаем первый токен - это должно быть значение контрольной суммы */
      if(( icode = aktool_strtok_r( (tchar *)string, " ", &substr )) == NULL ) return reterror;
      if(( error = ak_hexstr_to_ptr( icode,
                                      out2, sizeof( out2 ), ki->reverse_order )) != ak_error_ok ) {
        return ak_error_message_fmt( error, __func__, _("incorrect value of icode %s"), icode );
      }
    /* теперь второй токен - это имя файла */
      if(( filename = substr ) == NULL ) { /* не кооректно -> aktool_strtok_r( substr, " ", &substr ) */
        return ak_error_message( ak_error_undefined_file, __func__,
                                                      _("the name of file cannot be determined" ));
      }
    }
     else { /* обнаружилась скобка => вариант строки в формате BSD */

     /* сперва уничтожаем пробелы в конце слова и получаем имя */
      if( strlen( icode ) > 1024 ) return ak_error_undefined_value;
      if(( len = strlen( icode ) - 1 ) == 0 ) return ak_error_undefined_value;
      while(( icode[len] == ' ' ) && ( len )) icode[len--] = 0;

     /* теперь второй токен - это имя файла */
      if(( filename = aktool_strtok_r( substr, ")", &substr )) == NULL )
        return ak_error_undefined_value;

     /* теперь, контрольная сумма */
      while(( *substr == ' ' ) || ( *substr == '=' )) substr++;
      if(( error = ak_hexstr_to_ptr( substr,
                                      out2, sizeof( out2 ), ki->reverse_order )) != ak_error_ok ) {
        return ak_error_message_fmt( error, __func__, _("incorrect value of icode %s"), substr );
      }
       else icode = substr;
     } /* else */

    if(( error = ak_htable_add_str_value( &ki->icodes,
                                        filename, out2, ak_hexstr_size( icode ))) != ak_error_ok )
      ak_error_message( error, __func__, "wrong new key pair addition" );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция обрабатывает заданный пользователем файл и считывает из него
   сохраненную ранее хэш-таблицу с вычисленными контрольными суммами или имтовставками             */
/* ----------------------------------------------------------------------------------------------- */
 int aktool_icode_import_checksum( aktool_ki_t *ki )
{
    int error = ak_error_ok;

   /* в начале, проверяем что формат пользователем не задан или используется
      значение по-умолчанию */
    if( ki->field == format_binary ) {

     /* начинаем с того, что пытаемся открыть файл как двоичную хэш-таблицу*/
      if(( error = ak_htable_create_from_file( &ki->icodes, ki->pubkey_file )) == ak_error_ok )
        return ak_error_ok;

      switch( error ) {
       /* ошибки доступа к файлу */
        case ak_error_open_file:
        case ak_error_access_file:
        case ak_error_null_pointer:
          aktool_error(_("the file %s cannot be accessed"), ki->pubkey_file );
          return error;

       /* ошибки разбора и интерпретации данных */
        case ak_error_read_data:
        case ak_error_not_equal_data:
        case ak_error_wrong_length:
        case ak_error_out_of_memory:
          /* далее, сделаем еще одну попытку и попробуем разобрать файл как набор строк */
          ak_error_set_value( ak_error_ok );
          if( ak_log_get_level() > ak_log_standard ) ak_error_message_fmt( ak_error_ok, __func__,
                                     _("trying to read %s file in text format"), ki->pubkey_file );
          break;
      }
    }

   /* создаем таблицу для хранения контрольных сумм */
    if(( error = ak_htable_create( &ki->icodes, ki->icode_lists_count )) != ak_error_ok )
      return ak_error_message( error, __func__, _("incorrect hash table creation"));

   /* теперь пытаемся считать символьные строки */
    ki->statistical_data.total_lines = ki->statistical_data.skiped_lines = 0;
    if(( error = ak_file_read_by_lines( ki->pubkey_file,
                                       aktool_icode_import_checksum_line, ki )) != ak_error_ok ) {
      ak_htable_destroy( &ki->icodes );
      aktool_error(_("incorrect loading predefined values from %s file"), ki->os_file );
    }
     else {
      /* выводим статистику  */
       if(( !ki->quiet ) && ( !ki->dont_show_stat )) {
         printf(_("the total lines loaded: %llu, of which:\n"),
                                       (long long unsigned int) ki->statistical_data.total_lines );
         printf(_(" - skipped lines: %llu\n"),
                                      (long long unsigned int) ki->statistical_data.skiped_lines );
       }
     }

  return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                   aktool_icode_export_import.c  */
/* ----------------------------------------------------------------------------------------------- */
