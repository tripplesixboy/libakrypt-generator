 #include <stdio.h>
 #include <libakrypt-base.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Контекст одного элемента хэш-таблицы */
 typedef struct keypair
{
 /*! \brief Указатель на область памяти с данными.
     \details Последовательно помещаются сначала ключ, а потом хранимые данные */
  ak_uint8 *data;
 /*! \brief Длина ключа поиска */
  size_t key_length;
 /*! \brief Длина хранимых данных */
  size_t value_length;
} *ak_keypair;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция, вычисляющая хэш-код от заданной области памяти */
 typedef size_t ( ak_function_get_hash_value )( ak_pointer , size_t );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Контекст хэш-таблицы */
 typedef struct htable {
  /*! \brief Указатель на массив списков */
   struct list *list;
  /*! \brief Размер массива списков */
   size_t count;
  /*! \brief Функция для вычисляения хеш-кода для заданного значения ключа */
   ak_function_get_hash_value *hash;
 } *ak_htable;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция создает ключевую пару - (ключ, значение) */
 int ak_keypair_create( ak_keypair , ak_pointer , size_t , ak_pointer , size_t );
/*! \brief Функция выделяет память и создает в ней ключевую пару - (ключ, значение) */
 ak_keypair ak_keypair_new( ak_pointer , size_t , ak_pointer , size_t );
/*! \brief Функция удаляет ключевую пару */
 int ak_keypair_destroy( ak_keypair );
/*! \brief Функция удаляет ключевую пару и освоюождает память */
 ak_pointer ak_keypair_delete( ak_pointer );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция создает хэш-таблицу с заданным числом узлов (списков) */
 int ak_htable_create( ak_htable , size_t );
/*! \brief Функция выделяет память и создает в ней хэш-таблицу с заданным числом узлов (списков) */
 ak_htable ak_htable_new( size_t );
/*! \brief Установка пользовательской функции удаления данных, хранящихся в списке */
 int ak_htable_set_hash_function( ak_htable , ak_function_get_hash_value );
/*! \brief Функция добавляет в таблицу ключевую пару - (ключ, значение) */
 int ak_htable_add_key_value( ak_htable , ak_pointer , size_t , ak_pointer , size_t );
/*! \brief Функция добавляет в таблицу ключевую пару - (null-строка, значение) */
 int ak_htable_add_str_value( ak_htable , tchar * , ak_pointer , size_t );
/*! \brief Функция добавляет в таблицу ключевую пару (null-строка, null-строка) */
 int ak_htable_add_str_str( ak_htable , tchar * , tchar * );
/*! \brief Функция возвращает указатель на ключевую пару по заданному ключу */
 ak_keypair ak_htable_get_keypair( ak_htable , ak_pointer , size_t );
/*! \brief Функция возвращает указатель на ключевую пару по ключу, заданному null-строкой */
 ak_keypair ak_htable_get_keypair_str( ak_htable , tchar * );
/*! \brief Функция возвращает указатель на данные по заданному ключу */
 ak_pointer ak_htable_get( ak_htable , ak_pointer , size_t , size_t * );
/*! \brief Функция возвращает указатель на данные по ключу, заданному null-строкой */
 ak_pointer ak_htable_get_str( ak_htable , tchar *, size_t * );
/*! \brief Функция удаляет хэш-таблицу */
 int ak_htable_destroy( ak_htable );
/*! \brief Функция удаляет хэш-таблицу и освобождает выделенную память */
 ak_pointer ak_htable_delete( ak_pointer );

/* ----------------------------------------------------------------------------------------------- */
 int ak_keypair_create( ak_keypair kp,
                            ak_pointer key, size_t key_size, ak_pointer value, size_t value_size )
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
    if(( kp->data = malloc(( kp->key_length = key_size ) + ( kp->value_length = value_size )))
                                                                                         == NULL )
      return ak_error_message( ak_error_out_of_memory, __func__, "incorrect memory allocation" );
   /* копируем данные */
    memcpy( kp->data, key, kp->key_length );
    memcpy( kp->data + kp->key_length, value, kp->value_length );

  return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_keypair ak_keypair_new( ak_pointer key, size_t key_size, ak_pointer value, size_t value_size )
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
 static size_t ak_htable_get_key_index( ak_pointer key, size_t key_size )
{
    size_t i, index = 5381;

   /* как-то так */
    for( i = 0; i < key_size; i++ ) index = ((index << 5 ) + index ) + ((ak_uint8 *)key)[i];

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
 int ak_htable_add_key_value( ak_htable tbl,
                            ak_pointer key, size_t key_size, ak_pointer value, size_t value_size )
{
    size_t index = 0;

   /* необходимые проверки */
    if( tbl == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to hash table context" );
   /* вычисляем индекс ключа в массиве списков */
    index = ( tbl->hash( key, key_size ) % tbl->count );

   /* создаем элемент списка и добавляем его в соответствующий список */
    return ak_list_add_node( &tbl->list[index],
                            ak_list_node_new( ak_keypair_new( key, key_size, value, value_size )));
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_htable_add_str_value( ak_htable tbl, tchar *key, ak_pointer value, size_t value_size )
{
  return ak_htable_add_key_value( tbl, key, strlen(key) +1, value, value_size );
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_htable_add_str_str( ak_htable tbl, tchar *key, tchar *value )
{
  return ak_htable_add_key_value( tbl, key, strlen(key) +1, value, strlen( value ) +1);
}

/* ----------------------------------------------------------------------------------------------- */
 ak_keypair ak_htable_get_keypair( ak_htable tbl, ak_pointer key, size_t key_size )
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
 ak_keypair ak_htable_get_keypair_str( ak_htable tbl, tchar *key )
{
  return ak_htable_get_keypair( tbl, key, strlen(key) +1 );
}

/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_htable_get( ak_htable tbl, ak_pointer key, size_t key_size, size_t *value_size )
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
 ak_pointer ak_htable_get_str( ak_htable tbl, tchar *key, size_t *value_size )
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
/* пользовательская функция вычисления хеш-кода от ключа */
/* ----------------------------------------------------------------------------------------------- */
 static size_t my_hash_function( ak_pointer key, size_t key_size )
{
    size_t i, index = 0xef1a79ec;

   /* как-то так */
    for( i = 0; i < key_size; i++ )
       index = (( index*517 ) +  (index >> 12)) + ((ak_uint8 *)key)[i];

  return index;
}

/* ----------------------------------------------------------------------------------------------- */
 int main( void )
{
    ak_htable tbl = ak_htable_new( 32 );

    ak_htable_set_hash_function( tbl, my_hash_function );

    ak_htable_add_str_str( tbl, "h", "1" );
    ak_htable_add_str_str( tbl, "he", "2" );
    ak_htable_add_str_str( tbl, "hel", "3" );
    ak_htable_add_str_str( tbl, "hell", "4" );
    ak_htable_add_str_str( tbl, "hello", "5" );
    ak_htable_add_str_str( tbl, "ello", "4" );
    ak_htable_add_str_str( tbl, "llo", "3" );
    ak_htable_add_str_str( tbl, "lo", "4" );
    ak_htable_add_str_str( tbl, "o", "11" );
    ak_htable_add_str_str( tbl, "a", "11" );
    ak_htable_add_str_str( tbl, "b", "12" );
    ak_htable_add_str_str( tbl, "c", "13" );
    ak_htable_add_str_str( tbl, "d", "Буква D" );
    ak_htable_add_str_str( tbl, "Александр Сергеевич Пушкин", "Евгений Онегин" );
    ak_htable_add_str_str( tbl, "Михаил Юрьевич Лермонтов", "Мцыри" );
    ak_htable_add_str_str( tbl, "Александр Иванович Куприн", "Суламифь" );
    ak_htable_add_str_str( tbl, "Николай Семенович Лесков", "Леди Макбет мценского уезда" );
    ak_htable_add_str_str( tbl, "Федор Михайлович Достоевский", "Идиот" );
    ak_htable_add_str_str( tbl, "Антон Павлович Чехов", "Три сестры" );
    ak_htable_add_str_str( tbl, "Алексей Константинович Толстой", "Князь серебрянный" );

  /* реализуем последовательный обход всех элементов таблицы */
    printf(" таблица содержит %lu списков\n", tbl->count );
    size_t cnt = 0;
    for( size_t i = 0; i < tbl->count; i++ ) {
      ak_list list = &tbl->list[i];
      cnt += list->count;
      printf(" - список: %2lu содержит %lu элементов\n", i, list->count );
      if( list->count == 0 ) continue;
      ak_list_first( list );
      do{
         ak_keypair kp = (ak_keypair)list->current->data;
        /* такой вывод работает только для строк */
         printf("    - ключ: %s, значение: %s\n", kp->data, kp->data + kp->key_length );
        /* так тоже можно, но менее наглядно
          ak_ptr_to_hexstr( kp->data,  kp->key_length, ak_false ),
          ak_ptr_to_hexstr( kp->data + kp->key_length, kp->value_length, ak_false )); */
      }
       while( ak_list_next( list ));
    }
    printf(" таблица содержит %lu элементов\n", cnt );

  /* поиск в таблице элементов с заданными ключами */
    printf("книга: %s\n", (char *)ak_htable_get_str( tbl, "Антоша Чехонте", NULL ));
    printf("книга: %s\n", (char *)ak_htable_get_str( tbl, "Антон Павлович Чехов", NULL ));
    printf("книга: %s\n", (char *)ak_htable_get_str( tbl, "d", NULL ));

   ak_htable_delete( tbl );
 return EXIT_SUCCESS;
}
