/* --------------------------------------------------------------------------------- */
/* Пример example-g02n05.c                                                           */
/*                                                                                   */
/* Иллюстрация работы с хэш-таблицами на примере контроля целостности файлов         */
/* --------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <libakrypt.h>

/* функция, которая будет вычислять контрольные суммы для файлов
 * и помещать их в хэш-таблицу */
 int first_function( const tchar *name, ak_pointer ptr )
{
   struct hash ctx;
   ak_uint8 icode[8];
   ak_htable tbl = ptr;
  /* создаем контекст хэширования */
   ak_hash_create_crc64( &ctx );
  /* хэшируем файл и вычисляем контрольную сумму */
   ak_hash_file( &ctx, name, icode, sizeof( icode ));
  /* помещаем все в таблицу */
   ak_htable_add_str_value( tbl, name, icode, sizeof( icode ));
  /* уничтожаем контекст хеширования */
   ak_hash_destroy( &ctx );

 return ak_error_ok;
}

 int main( void )
{
    struct htable tbl;

   /* выводим первичное сообщение */
    printf(" формируем таблицу ... "); fflush( stdout );
   /* создаем хэш-таблицу с большим количеством узлов первого уровня */
    ak_htable_create( &tbl, 1024 );
   /* рекурсивно обходим текущий каталог и помещаем контрольные суммы в хэш-таблицу */
    ak_file_find( ".", "*", first_function, &tbl, ak_true );
   /* выводим краткое резюме */
    printf("Ok\n обработано %lu файлов\n", (unsigned long int) ak_htable_count( &tbl ));
   /* сохраняем таблицу в файл */
    ak_htable_export_to_file( &tbl, "/var/tmp/example-g02n05.htable");
   /* удаляем таблицу из памяти */
    ak_htable_destroy( &tbl );

  return EXIT_SUCCESS;
}

   /* выводим содержимое таблицы путем последовательного обхода всех элементов
    printf(" таблица содержит %lu списков\n", tbl.count );
    for( size_t i = 0; i < tbl.count; i++ ) {
      ak_list list = &tbl.list[i];
      cnt += list->count;
      if( list->count == 0 ) continue;
      printf(" - список: %2lu содержит %lu элементов\n", i, list->count );
      ak_list_first( list );
      do{
         ak_keypair kp = (ak_keypair)list->current->data;
         printf("    - ключ: %s, значение: %s\n", kp->data,
              ak_ptr_to_hexstr( kp->data + kp->key_length,  kp->value_length, ak_false ));
      }
       while( ak_list_next( list ));
    }
    printf(" таблица содержит %lu элементов\n", cnt ); */
