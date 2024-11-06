/* Пример иллюстрирует строение хэш-таблицы, а также процедуры размещения и поиска данных */

 #include <stdio.h>
 #include <libakrypt-base.h>

/* пользовательская функция вычисления хэш-кода от ключа */
 static size_t my_hash_function( ak_const_pointer key, const size_t key_size )
{
    size_t i, index = 0xef1a79ec;

   /* как-то так */
    for( i = 0; i < key_size; i++ )
       index = (( index*17 ) +  (index >> 12)) + ((ak_uint8 *)key)[i];

  return index;
}

/* основная программа */
 int main( void )
{
   /* создаем контекст хэш-таблицы */
    ak_htable tbl = ak_htable_new( 9 );

   /* в процессе создания контекста устанавливается функция хэширования,
      однако, при желании, можно её заменить на свою функцию */
    ak_htable_set_hash_function( tbl, my_hash_function );

   /* добавляем данные в таблицу: ключ, значение */
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
   /* добавляем два разных элемента с одним и тем же ключом */
    printf(" код возврата: %d\n", ak_htable_add_str_str( tbl, "d", "Буква D" ));
    printf(" код возврата: %d\n", ak_htable_add_str_str( tbl, "d", "Буква D с тем же ключом" ));
    ak_htable_add_str_str( tbl, "Александр Сергеевич Пушкин", "Евгений Онегин" );
    ak_htable_add_str_str( tbl, "Михаил Юрьевич Лермонтов", "Мцыри" );
    ak_htable_add_str_str( tbl, "Александр Иванович Куприн", "Суламифь" );
    ak_htable_add_str_str( tbl, "Николай Семенович Лесков", "Леди Макбет Мценского уезда" );
    ak_htable_add_str_str( tbl, "Федор Михайлович Достоевский", "Идиот" );
    ak_htable_add_str_str( tbl, "Антон Павлович Чехов", "Три сестры" );
    ak_htable_add_str_str( tbl, "Алексей Константинович Толстой", "Князь серебрянный" );

  /* реализуем последовательный обход всех элементов таблицы */
    printf(" таблица содержит %u списков\n", (unsigned int) tbl->count );
    size_t cnt = 0;
    for( size_t i = 0; i < tbl->count; i++ ) {
      ak_list list = &tbl->list[i];
      cnt += list->count;
      printf(" - список: %2u содержит %u элементов\n",
                                                    (unsigned int) i, (unsigned int) list->count );
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
    printf(" таблица содержит %u элементов\n", (unsigned int) cnt );

  /* и только сейчас, главная цель применения хэш-таблиц */
  /* быстрый поиск элементов с заданными ключами */
    printf("книга: %s\n", (char *)ak_htable_get_str( tbl, "Антоша Чехонте", NULL ));
    printf("книга: %s\n", (char *)ak_htable_get_str( tbl, "Антон Павлович Чехов", NULL ));
    printf("книга: %s\n", (char *)ak_htable_get_str( tbl, "d", NULL ));

   ak_htable_delete( tbl );
 return EXIT_SUCCESS;
}
