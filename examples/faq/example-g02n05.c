/* --------------------------------------------------------------------------------- */
/* Пример example-g02n05.c                                                           */
/*                                                                                   */
/* Иллюстрация работы с хэш-таблицами на примере контроля целостности файлов         */
/* --------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <libakrypt.h>

/* структура для передачи данных в обе функции рекурсивной обработки данных */
 typedef struct hs {
   struct hash ctx;
   struct htable tbl;
   ak_uint64 count;
 } *ak_hs;

/* функция, которая будет вычислять контрольные суммы для файлов
 * и помещать их в хэш-таблицу */
 int first_function( const tchar *name, ak_pointer ptr )
{
   ak_hs hp = ptr;
   ak_uint8 icode[64];
   size_t ilen = ak_hash_get_tag_size( &hp->ctx );

  /* хэшируем файл и вычисляем контрольную сумму */
   ak_hash_file( &hp->ctx, name, icode, ilen );
  /* помещаем все в таблицу */
   ak_htable_add_str_value( &hp->tbl, name, icode, ilen );
 return ak_error_ok;
}

/* функция, которая будет вычислять контрольные суммы для файлов
 * и сравнивать их со значениями из заданной хеш-таблицы */
 int second_function( const tchar *name, ak_pointer ptr )
{
   ak_hs hp = ptr;
   ak_uint8 icode[64], *val = NULL;
   size_t ilen = ak_hash_get_tag_size( &hp->ctx );

  /* хэшируем файл и вычисляем контрольную сумму */
   memset( icode, 0, ilen );
   ak_hash_file( &hp->ctx, name, icode, ilen );

  /* проверяем */
   if(( val = ak_htable_get_str( &hp->tbl, name, NULL )) != NULL ){
     if( memcmp( icode, val, ilen ) == 0 ) {
       printf(" [Ok] ");
         hp->count++;
     } else printf(" [%sNo%s]",  ak_error_get_start_string(), ak_error_get_end_string());
     printf("%s\n", name );
   }
    else {
     printf(" [%snot found%s] %s\n",
                          ak_error_get_start_string(), ak_error_get_end_string(), name );
    }
 return ak_error_ok;
}

/* основная программа */
 int main( void )
{
    struct hs hp;
    struct file fp;
  #ifdef AK_HAVE_WINDOWS_H
    char *filename = "example-g02n05.htable";
  #else
    char *filename = "/var/tmp/example-g02n05.htable";
  #endif

   /* настаиваем бибилиотеку на подробный сообщений */
    ak_log_set_level( ak_log_maximum );
    ak_libakrypt_create( ak_function_log_stderr );

   /* создаем хэш-таблицу с большим количеством узлов первого уровня */
    ak_htable_create( &hp.tbl, 1024 );
   /* создаем контекст алгоритма хэширования */
    ak_hash_create_crc64( &hp.ctx );
    hp.count = 0;
   /* выводим первичное сообщение */
    printf(" hash table creating ... "); fflush( stdout );
   /* рекурсивно обходим текущий каталог и помещаем контрольные суммы в хэш-таблицу */
    ak_file_find( ".", "*", first_function, &hp, ak_false );
   /* выводим краткое резюме */
    printf("Ok\n founded %lu files\n", (unsigned long int) ak_htable_count( &hp.tbl ));
   /* сохраняем таблицу в файл */
    printf("code: %d\n", ak_htable_export_to_file( &hp.tbl, filename ));
   /* удаляем таблицу из памяти */
    printf("code: %d\n", ak_htable_destroy( &hp.tbl ));

   /* создаем новый файл */
    printf(" create: %d\n", ak_file_create_to_write( &fp, "new-file.txt" ));
    printf(" write: %u\n",
                (unsigned int )ak_file_printf( &fp, "Created with block_size: %u\n", fp.blksize ));
    printf(" close: %d\n", ak_file_close( &fp ));

   /* выводим сообщение */
    printf(" reading the table ... "); fflush( stdout );
   /* создаем новую таблицу, используя сохраненные на диске значения */
    if( ak_htable_create_from_file( &hp.tbl, filename ) != ak_error_ok ) {
      printf("incorrect reading hash table from %s file\n", filename );
      return EXIT_FAILURE;
    }
   /* выводим краткое резюме */
    printf("Ok\n");
   /* рекурсивно обходим текущий каталог и проверяем контрольные суммы */
    ak_file_find( ".", "*", second_function, &hp, ak_false );
    printf(" successfully checked %lu files\n", (unsigned long int) hp.count );
   /* удаляем таблицу из памяти */
    ak_htable_destroy( &hp.tbl );
   /* уничтожаем контекст хеширования */
    ak_hash_destroy( &hp.ctx );
   /* заверщаем работу с библиотекой */
    ak_libakrypt_destroy();
  return EXIT_SUCCESS;
}

/*  следующий фрагмент позволяет вывести
    содержимое таблицы путем последовательного обхода всех ее элементов

    printf(" таблица содержит %lu списков\n", hp.tbl.count );
    for( size_t i = 0; i < hp.tbl.count; i++ ) {
      ak_list list = &hp.tbl.list[i];
      cnt += list->count;
      if( list->count == 0 ) continue;
      printf(" - список: %2lu содержит %lu элементов\n", i, list->count );
      ak_list_first( list );
      do{
         ak_keypair kp = (ak_keypair)list->current->data;
         printf("    - [key: %s, val: %s]\n", kp->data,
              ak_ptr_to_hexstr( kp->data + kp->key_length,  kp->value_length, ak_false ));
      }
       while( ak_list_next( list ));
    }
    printf(" таблица содержит %llu элементов\n", cnt ); */
