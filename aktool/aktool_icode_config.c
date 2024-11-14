/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2024 by Axel Kenzo, axelkenzo@mail.ru                                            */
/*                                                                                                 */
/*  Прикладной модуль, реализующий процедуры чтения файла конфигурации                             */
/*                                                                                                 */
/*  aktool_icode_config.c                                                                          */
/* ----------------------------------------------------------------------------------------------- */
 #include "aktool.h"
 #include <libakrypt.h>

#ifdef AK_HAVE_ERRNO_H
 #include <errno.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
/*                 функции для чтения и проверки корректности файла с конфигурацией                */
/* ----------------------------------------------------------------------------------------------- */
 static int aktool_icode_ini_options( aktool_ki_t *ki,
                                         const char *section, const char *name, const char *value )
{
   /* --database устанавливаем имя для файла с результатами */
    if(( memcmp( name, "input", 5 ) == 0 ) ||
       ( memcmp( name, "output", 6 ) == 0  ) ||
       ( memcmp( name, "database", 8 ) == 0 )) {
     #ifdef _WIN32
      GetFullPathName( value, FILENAME_MAX, ki->pubkey_file, NULL );
     #else
      if( ak_realpath( value, ki->pubkey_file, sizeof( ki->pubkey_file ) -1 ) != ak_error_ok ) {
        aktool_error(_("the full name of checksum file \"%s\" cannot be created"), value );
        return 0;
      }
     #endif
      return 1;
    }

   /* --format устанавливаем формат хранения вычисленных/проверочных значений */
    if( memcmp( name, "format", 6 ) == 0 ) {
      if( memcmp( value, "bsd", 3 ) == 0 ) ki->field = format_bsd;
      if( memcmp( value, "linux", 5 ) == 0 ) ki->field = format_linux;
      if( memcmp( value, "binary", 6 ) == 0 ) ki->field = format_binary;
      return 1;
    }

   /* --hash-table-nodes устанавливаем количество узлов верхнего уровня в хеш-таблице
                      результирующее значение всегда находится между 16 и 4096 */
    if( memcmp( name, "hash-table-nodes", 16 ) == 0 ) {
      ki->icode_lists_count = ak_min( 4096, ak_max( 16, atoi( value )));
      return 1;
   }

   /* --recursive устанавливаем флаг рекурсивного обхода каталогов */
    if( memcmp( name, "recursive", 9 ) == 0 ) {
      if(( memcmp( value, "true", 4 ) == 0 ) || ( memcmp( value, "TRUE", 4 ) == 0 ))
        ki->tree = ak_true;
      return 1;
    }

   /* шаблон поиска файлов */
    if( memcmp( name, "pattern", 7 ) == 0 ) {
      if( ki->pattern != NULL ) free( ki->pattern );
      ki->pattern = strdup( value );
      return 1;
    }

   /* --algorithm  устанавливаем имя алгоритма бесключевого хеширования */
    if( memcmp( name, "algorithm", 9 ) == 0 ) {
      if(( ki->method = ak_oid_find_by_ni( value )) == NULL ) {
        aktool_error(_("using unsupported name or identifier \"%s\""), value );
        printf(_("try \"aktool s --oid hash\" for list of all available identifiers\n"));
        return 0;
      }
      if( ki->method->engine != hash_function ) {
        aktool_error(_("option --algorithm accepts only keyless integrity mechanism"));
        printf(_("try \"aktool s --oid hash\" for list of all available identifiers\n"));
        return 0;
      }
      return 1;
    }

   /* --key устанавливаем имя файла, содержащего секретный ключ */
    if( memcmp( name, "key", 3 ) == 0 ) {
     #ifdef _WIN32
      GetFullPathName( value, FILENAME_MAX, ki->key_file, NULL );
     #else
      if( ak_realpath( value, ki->key_file, sizeof( ki->key_file ) -1 ) != ak_error_ok ) {
        aktool_error(_("the full name of key file \"%s\" cannot be created"), value );
        return 0;
      }
     #endif
      return 1;
    }

   /* --no-derive */
    if( memcmp( name, "no-derive", 9 ) == 0 ) {
      if(( memcmp( value, "false", 5 ) == 0 ) || ( memcmp( value, "FALSE", 5 ) == 0 )) {
        ki->key_derive = ak_false;
      }
      return 1;
    }

#ifdef AK_HAVE_GELF_H
   /* --with-segments */
    if( memcmp( name, "with-segments", 13 ) == 0 ) {
      if(( memcmp( value, "true", 4 ) == 0 ) || ( memcmp( value, "TRUE", 4 ) == 0 )) {
        ki->ignore_segments = ak_false;
      }
    }

   /* --only-segments */
    if( memcmp( name, "only-segments", 13 ) == 0 ) {
      if(( memcmp( value, "true", 4 ) == 0 ) || ( memcmp( value, "TRUE", 4 ) == 0 )) {
        ki->only_segments = ak_true;
        ki->ignore_segments = ak_false;
      }
    }
#endif

    if( ak_log_get_level() > ak_log_standard )
      ak_error_message_fmt( ak_error_undefined_value, __func__,
                             "unsupported record in section [%s]: %s = %s", section, name, value );
  return 1;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_icode_ini_control( aktool_ki_t *ki,
                                         const char *section, const char *name, const char *value )
{
    int permissions = 0;

    (void) section;
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

   #ifdef AK_HAVE_GELF_H
    if( memcmp( name, "exclude-link", 12 ) == 0 ) {
      switch( permissions ) {
        case DT_REG:
          if( ak_htable_add_str_str( &ki->exclude_link, value, "file" ) != ak_error_ok ) return 0;
           else return 1;
        default:
          return 1;
      }
    }
   #endif

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
    aktool_error(_("incorrect parsing config file"));

  return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                          aktool_icode_config.c  */
/* ----------------------------------------------------------------------------------------------- */
