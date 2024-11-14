/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2024 by Axel Kenzo, axelkenzo@mail.ru                                            */
/*                                                                                                 */
/*  Файл ak_htable.с                                                                               */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt-base.h>

/* ----------------------------------------------------------------------------------------------- */
/*                                   вспомогательные функции                                       */
/* ----------------------------------------------------------------------------------------------- */
 static inline ak_uint64 ak_uint64_ton( ak_uint64 x ) {
  #ifdef AK_BIG_ENDIAN
    return x;
  #else
    return bswap_64(x);
  #endif
}

/* ----------------------------------------------------------------------------------------------- */
/*                               реализация основного функционала                                  */
/* ----------------------------------------------------------------------------------------------- */
/*! @param kp Указатель на контекст пары (ключ:данные), не должен принимать значение, равное NULL
    @param key Указатель на область памяти, содержащей ключевое значение; не должен быть равен NULL
    @param key_size Размер ключевого значения (в октетах)
    @param value Указатель на область память, содержащей данные
    @param value_size Размер данных (в октетах)
    @return В случае успеха возвращается ноль (значение ak_error_ok). В случае возникновения
    ошибки возвращается ее код.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_keypair_create( ak_keypair kp,
    ak_const_pointer key, const size_t key_size, ak_const_pointer value, const size_t value_size )
{
   /* необходимые проверки */
    if( kp == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                                "using null pointer to key pair" );
    if( key == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                                "using null pointer to key data" );
    if( !key_size ) return ak_error_message( ak_error_zero_length, __func__,
                                                               "using key data with zero length" );
    if( value == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                                   "using null pointer to value" );
    if( !value_size ) return ak_error_message( ak_error_zero_length, __func__,
                                                                  "using value with zero length" );
   /* выделяем память */
    if(( kp->data = ak_aligned_malloc(
                     ( kp->key_length = key_size ) + ( kp->value_length = value_size ))) == NULL )
      return ak_error_message( ak_error_out_of_memory, __func__, "incorrect memory allocation" );
   /* копируем данные */
    memcpy( kp->data, key, kp->key_length );
    memcpy( kp->data + kp->key_length, value, kp->value_length );

  return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_keypair ak_keypair_new( ak_const_pointer key,
                           const size_t key_size, ak_const_pointer value, const size_t value_size )
{
  ak_keypair kp = malloc( sizeof( struct keypair ));

  if( !kp ) {
    ak_error_message( ak_error_out_of_memory, __func__, "incorrect memory allocation" );
    return NULL;
  }
  if( ak_keypair_create( kp, key, key_size, value, value_size ) != ak_error_ok ) {
    free( kp );
    kp = NULL;
  }
 return kp;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_keypair_destroy( ak_keypair kp )
{
   /* необходимые проверки */
    if( kp == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                                "using null pointer to key pair" );
    if( kp->data != NULL ) free( kp->data );
    kp->key_length = 0;
    kp->value_length = 0;

  return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_keypair_delete( ak_pointer kp  )
{
    if( kp == NULL ) {
      ak_error_message( ak_error_null_pointer, __func__, "using null pointer to key pair" );
      return NULL;
    }
    ak_keypair_destroy( (ak_keypair)kp );
    free( kp );

 return ( kp = NULL );
}

/* ----------------------------------------------------------------------------------------------- */
/*                            теперь методы класса htable                                          */
/* ----------------------------------------------------------------------------------------------- */
 static size_t ak_htable_get_key_index( ak_const_pointer key, const size_t key_size )
{
    size_t i, index = 5381;

   /* как-то так */
    for( i = 0; i < key_size; i++ ) index += ((index << 5 ) + ((ak_uint8 *)key)[i] );

  return index;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_htable_create( ak_htable tbl, size_t count )
{
    size_t i = 0;
    int error = ak_error_ok;

   /* необходимые проверки */
    if( tbl == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to hash table context" );
    if( !( tbl->count = count )) return ak_error_message( ak_error_zero_length, __func__,
                                                           "creating hash table with zero length");
   /* устанавливаем функцию вычисления хэш-кода */
    tbl->hash = ak_htable_get_key_index;

   /* создаем массив списков */
    if(( tbl->list = (ak_list)calloc( count, sizeof( struct list ))) == NULL )
      return ak_error_message( ak_error_out_of_memory, __func__, "incorrect memory allocation" );

   /* инициализируем массив списков */
    for( i = 0; i < tbl->count; i++ ) {
      if(( error = ak_list_create( &tbl->list[i] )) != ak_error_ok ) {
       ak_htable_destroy( tbl );
       return ak_error_message_fmt( error, __func__,
                      "incorrect creating a hash table list (number %4lu)", (unsigned long int)i );
      }
      /* устанавливаем функцию для удаления памяти из под хранящихся объектов */
       else ak_list_set_delete_function( &tbl->list[i], ak_keypair_delete );
    }

  return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_htable ak_htable_new( size_t count )
{
  ak_htable tbl = malloc( sizeof( struct htable ));

  if( !tbl ) {
    ak_error_message( ak_error_out_of_memory, __func__, "incorrect memory allocation" );
    return NULL;
  }
  if( ak_htable_create( tbl, count ) != ak_error_ok ) {
    free( tbl );
    tbl = NULL;
  }
 return tbl;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_htable_set_hash_function( ak_htable tbl, ak_function_get_hash_value func )
{
  if( !tbl ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to hash table context" );
  tbl->hash = func;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_htable_destroy( ak_htable tbl )
{
    size_t i = 0;

   /* необходимые проверки */
    if( tbl == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to hash table context" );
   /* проверка и удаление */
    for( i = 0; i < tbl->count; i++ ) ak_list_destroy( &tbl->list[i] );
   /* очистка */
    memset( tbl->list, 0, tbl->count*sizeof( ak_pointer ));
    free( tbl->list );
    tbl->hash = NULL;
    tbl->count = 0;

  return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_htable_delete( ak_pointer tbl )
{
    if( tbl == NULL ) {
      ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to hash table context" );
      return NULL;
    }
    ak_htable_destroy( (ak_htable)tbl );
    free( tbl );

 return ( tbl = NULL );
}

/* ----------------------------------------------------------------------------------------------- */
 size_t ak_htable_count( ak_htable tbl )
{
    size_t i, total = 0;

   /* необходимые проверки */
    if( tbl == NULL ) {
      ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to hash table context" );
      return 0;
    }
   /* основной цикл */
    for( i = 0; i < tbl->count; i++ ) total += tbl->list[i].count;

 return total;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_htable_add_key_value( ak_htable tbl,
     ak_const_pointer key, const size_t key_size, ak_const_pointer value, const size_t value_size )
{
    size_t index = 0;
    ak_list list = NULL;
    ak_keypair kp = NULL;

   /* необходимые проверки */
    if( tbl == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to hash table context" );
    if( tbl->count == 0) return ak_error_message( ak_error_zero_length, __func__,
                                                 "using uncreated hash table with zero elements" );

   /* вычисляем индекс ключа в массиве списков */
    index = tbl->hash( key, key_size ) % tbl->count;

   /* проверяем уникальность ключа */
    list = &tbl->list[index];
    if( list->count != 0 ) {
      ak_list_first( list );
      do{
         if(( kp = (ak_keypair)list->current->data ) == NULL )
           return ak_error_htable_null_element;
         if(( kp->key_length == key_size ) && ( memcmp( kp->data, key, kp->key_length ) == 0 ))
           return ak_error_htable_key_exist;
      }
       while( ak_list_next( list ));
    }

   /* только после проверки, создаем элемент списка и добавляем его в соответствующий список */
    return ak_list_add_node( &tbl->list[index],
                            ak_list_node_new( ak_keypair_new( key, key_size, value, value_size )));
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_htable_add_key_str( ak_htable tbl,
                                  ak_const_pointer key, const size_t key_size, const tchar *value )
{
  return ak_htable_add_key_value( tbl, key, key_size, value, strlen( value ) +1);
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_htable_add_str_value( ak_htable tbl,
                                const tchar *key, ak_const_pointer value, const size_t value_size )
{
  return ak_htable_add_key_value( tbl, key, strlen(key) +1, value, value_size );
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_htable_add_str_str( ak_htable tbl, const tchar *key, const tchar *value )
{
  return ak_htable_add_key_value( tbl, key, strlen(key) +1, value, strlen( value ) +1);
}

/* ----------------------------------------------------------------------------------------------- */
 ak_keypair ak_htable_get_keypair( ak_htable tbl, ak_const_pointer key, const size_t key_size )
{
    ak_list lst = NULL;
    ak_keypair kp = NULL;

   /* необходимые проверки */
    if( tbl == NULL ) {
      ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to hash table context" );
      return NULL;
    }
   /* вычисляем индекс ключа в массиве списков */
    lst = &tbl->list[ tbl->hash( key, key_size ) % tbl->count ];
   /* проверяем, что список не пуст */
    if( lst->count == 0 ) return NULL;
   /* выполняем поиск по списку */
    ak_list_first( lst );
    do {
      /* проверяем, что ключевая пара определена */
       if(( kp = (ak_keypair) lst->current->data ) == NULL ) continue;
      /* проверяем совпадение длин */
       if( kp->key_length != key_size ) continue;
      /* проверяем совпадение значений */
       if( memcmp( kp->data, key, key_size ) == 0 ) return kp;
    } while( ak_list_next( lst ));

 /* ничего не найдено */
  return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_keypair ak_htable_get_keypair_str( ak_htable tbl, const tchar *key )
{
  return ak_htable_get_keypair( tbl, key, strlen(key) +1 );
}

/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_htable_get( ak_htable tbl,
                                  ak_const_pointer key, const size_t key_size, size_t *value_size )
{
  ak_keypair kp = ak_htable_get_keypair( tbl, key, key_size );
  if( kp != NULL ) {
    /* устанавливаем длину */
     if( value_size != NULL ) *value_size = kp->value_length;
    /* возвращаем указатель */
     return kp->data + kp->key_length;
  }
   else return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_htable_get_str( ak_htable tbl, const tchar *key, size_t *value_size )
{
  ak_keypair kp = ak_htable_get_keypair_str( tbl, key );
  if( kp != NULL ) {
    /* устанавливаем длину */
     if( value_size != NULL ) *value_size = kp->value_length;
    /* возвращаем указатель */
     return kp->data + kp->key_length;
  }
   else return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_keypair ak_htable_exclude_keypair( ak_htable tbl, ak_const_pointer key, const size_t key_size )
{
    ak_list lst = NULL;
    ak_keypair kp = NULL;

   /* необходимые проверки */
    if( tbl == NULL ) {
      ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to hash table context" );
      return NULL;
    }
   /* вычисляем индекс ключа в массиве списков */
    lst = &tbl->list[ tbl->hash( key, key_size ) % tbl->count ];
   /* проверяем, что список не пуст */
    if( lst->count == 0 ) return NULL;
   /* выполняем поиск по списку */
    ak_list_first( lst );
    do {
      /* проверяем, что ключевая пара определена */
       if(( kp = (ak_keypair) lst->current->data ) == NULL ) continue;
      /* проверяем совпадение длин */
       if( kp->key_length != key_size ) continue;
      /* в случае совпадения значений изымаем элемент из списка */
       if( memcmp( kp->data, key, key_size ) == 0 ) {
        /* удаляем list_node */
         ak_list_node ln = ak_list_exclude(lst);
         ln->data = NULL;
         ak_list_node_delete( lst, ln );
        /* собственно значение ключевой пары отправляем пользователю */
         return kp;
       }
    } while( ak_list_next( lst ));

 /* ничего не найдено */
  return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_keypair ak_htable_exclude_keypair_str( ak_htable tbl, const tchar *key )
{
  return ak_htable_exclude_keypair( tbl, key, strlen(key) +1 );
}

/* ----------------------------------------------------------------------------------------------- */
/*                        функции экспорта и импорта хэш-таблицы                                   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_htable_export_to_file( ak_htable tbl, const tchar *name )
{
    size_t i;
    struct file fp;
    ssize_t result;
    ak_uint64 count = 0;
    ak_list list = NULL;
    ak_keypair kp = NULL;
    int error = ak_error_ok;

   /* необходимые проверки */
    if( tbl == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to hash table context" );
    if( name == NULL )  return ak_error_message( ak_error_null_pointer, __func__,
                                                               "using null pointer to file name" );
    if(( error = ak_file_create_to_write( &fp, name )) != ak_error_ok )
      return ak_error_message( error, __func__, "incorrect file creation" );

   /* 1. метка файла (2 байта) */
    if( ak_file_write( &fp, "ht", 2 ) != 2 ) {
      error = ak_error_message( ak_error_get_value(), __func__, "unable to write header of file");
      goto exlab;
    }

   /* 2. количество списков */
    count = ak_uint64_ton( tbl->count );
    if( ak_file_write( &fp, &count, sizeof( ak_uint64 )) != sizeof( ak_uint64 )) {
      error = ak_error_message( ak_error_get_value(), __func__, "unable to write count of lists");
      goto exlab;
    }

   /* 3. элементы списка в заданном формате */
    for( i = 0; i < tbl->count; i++ ) {
       list = &tbl->list[i];

      /* 3.1 сначала количество элементов с списке */
       count = ak_uint64_ton( list->count );
       if( ak_file_write( &fp, &count, sizeof( ak_uint64 )) != sizeof( ak_uint64 )) {
         error = ak_error_message_fmt( ak_error_get_value(), __func__,
                   "unable to write count of elements for list number %lu", (unsigned long int) i);
         goto exlab;
       }
       if( !count ) continue;

      /* 3.2 потом, последовательно сохраняем длины и данные */
       ak_list_first( list );
       do{
         /* получаем пару ключ:данные */
          if(( kp = ( ak_keypair )list->current->data ) == NULL ) continue;

         /* длина ключа */
          count = ak_uint64_ton( kp->key_length );
          if( ak_file_write( &fp, &count, sizeof( ak_uint64 )) != sizeof( ak_uint64 )) {
            error = ak_error_message( ak_error_get_value(), __func__,
                                                                    "unable to write key length" );
            goto exlab;
          }

         /* длина данных */
          count = ak_uint64_ton( kp->value_length );
          if( ak_file_write( &fp, &count, sizeof( ak_uint64 )) != sizeof( ak_uint64 )) {
             error = ak_error_message( ak_error_get_value(), __func__,
                                                                  "unable to write value length" );
            goto exlab;
          }

         /* собственно данные */
          result = ak_file_write( &fp, kp->data, kp->key_length + kp->value_length );
          if(( result < 0 ) || ( (size_t) result != ( kp->key_length + kp->value_length ))) {
            error = ak_error_message( ak_error_get_value(), __func__, "unable to write user data" );
            goto exlab;
          }
       } while( ak_list_next( list ));
    }

  exlab:
    ak_file_close( &fp );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_htable_create_from_file( ak_htable tbl, const tchar *name )
{
    size_t i, j;
    struct file fp;
    ssize_t result;
    ak_uint64 count = 0;
    ak_uint8 buffer[1024];
    int error = ak_error_ok;

   /* необходимые проверки */
    if( tbl == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to hash table context" );
   /* открываем файл */
    if(( error = ak_file_open_to_read( &fp, name )) != ak_error_ok )
      return ak_error_message( error, __func__, "unable to open a file" );

   /* 1. метка файла (2 байта) */
    if( ak_file_read( &fp, buffer, 2 ) != 2 ) {
      error = ak_error_message( ak_error_read_data, __func__, "unable to read header of file");
      goto exlab;
    }
    if( memcmp( buffer, "ht", 2 ) != 0 ) {
      error = ak_error_message( ak_error_not_equal_data, __func__, "wrong predefined header" );
      goto exlab;
    }

   /* 2. количество списков (8 байт) */
    if( ak_file_read( &fp, buffer, 8 ) != 8 ) {
      error = ak_error_message( ak_error_read_data, __func__, "unable to read count of lists");
      goto exlab;
    }
    if(( count = ak_uint64_ton( *((ak_uint64*)buffer))) > 65536 ) {
      error = ak_error_message( ak_error_wrong_length, __func__, "very large hash table");
      goto exlab;
    }

   /* 3. функция является конструктором */
    if(( error = ak_htable_create( tbl, count )) != ak_error_ok ) {
      ak_error_message_fmt( error, __func__, "unable to create hash table with %llu lists", count );
      goto exlab;
    }

   /* последовательно считываем списки */
   /* 4. элементы списка в заданном формате */
    for( i = 0; i < tbl->count; i++ ) {

      /* 4.1 количество элементов в списке */
       if( ak_file_read( &fp, buffer, 8 ) != 8 ) {
         error = ak_error_message_fmt( ak_error_read_data, __func__,
                                      "unable to read count of elements for list number %llu", i );
         ak_htable_destroy(tbl);
         goto exlab;
       }
       if(( count = ak_uint64_ton( *((ak_uint64*)buffer))) > 65536 ) {
         error = ak_error_message( ak_error_wrong_length, __func__,
                                                                  "very large count of elements ");
         ak_htable_destroy(tbl);
         goto exlab;
       }

      /* 4.2 последовательно считываем элементы текущего списка */
       for( j = 0; j < count; j++ ) {
         ak_uint8 *key = NULL;
         size_t key_size = 0, value_size = 0;

        /* длина ключа */
         if( ak_file_read( &fp, buffer, 8 ) != 8 ) {
           error = ak_error_message( ak_error_read_data, __func__,
                                                                 "unable to read the key length" );
           ak_htable_destroy(tbl);
           goto exlab;
         }
         if(( key_size = ak_uint64_ton( *((ak_uint64*)buffer))) > 65536 ) {
           error = ak_error_message( ak_error_wrong_length, __func__, "very large key length");
           ak_htable_destroy(tbl);
           goto exlab;
         }

        /* длина данных */
         if( ak_file_read( &fp, buffer, 8 ) != 8 ) {
           error = ak_error_message( ak_error_read_data, __func__,
                                                               "unable to read the value length" );
           ak_htable_destroy(tbl);
           goto exlab;
         }
         if(( value_size = ak_uint64_ton( *((ak_uint64*)buffer))) > 65536 ) {
           error = ak_error_message( ak_error_wrong_length, __func__, "very large value length");
           ak_htable_destroy(tbl);
           goto exlab;
         }

        /* готовим память */
         if(( key = malloc( key_size + value_size )) == NULL ) {
           error = ak_error_message( ak_error_out_of_memory, __func__, "out of memory");
           ak_htable_destroy(tbl);
           goto exlab;
         }

        /* считываем память */
         result = ak_file_read( &fp, key, key_size + value_size );
         if(( result < 0 ) || ((size_t) result != key_size + value_size )) {
           error = ak_error_message( ak_error_read_data, __func__,
                                                               "unable to read the keypair data" );
           free(key);
           ak_htable_destroy(tbl);
           goto exlab;
         }

        /* добавляем считанное в список */
         if(( error = ak_htable_add_key_value( tbl,
                                    key, key_size, key +key_size, value_size )) != ak_error_ok ) {
           ak_error_message( error, __func__, "unable to add the keypair data" );
           free(key);
           ak_htable_destroy(tbl);
           goto exlab;
         }
         free(key);
       }
    }

  exlab:
    ak_file_close( &fp );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \example example-htable.c                                                                      */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                    ak_htable.c  */
/* ----------------------------------------------------------------------------------------------- */
