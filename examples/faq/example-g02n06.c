/* -------------------------------------------------------------------------------- */
/* Пример example-g02n06.c                                                           */
/*                                                                                   */
/* Работа с хэш-таблицами. Пример добавления и исключения элементов                  */
/* --------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <libakrypt.h>


 int main( void )
{
    size_t cnt = 0;
    struct htable ht;
    struct keypair *kp = NULL;

    ak_htable_create( &ht, 32 );

  /* добавляем несколько элементов */
    ak_htable_add_str_str( &ht, "key1", "string 01");
    ak_htable_add_str_str( &ht, "key2", "string 02");
    ak_htable_add_str_str( &ht, "key3", "string 03");
    ak_htable_add_str_str( &ht, "key4", "string 04");
    ak_htable_add_str_str( &ht, "key5", "string 05");

  /* что-нибудь ищем */
    printf("value: %s\n", (char *)ak_htable_get_str( &ht, "key3", NULL ));

  /* исключаем пару элементов, самостоятельно удаляя память */
    kp = ak_htable_exclude_keypair_str( &ht, "key2" );
    printf("found: [key: %s, value: %s]\n", kp->data, kp->data + kp->key_length );
    ak_keypair_delete( kp );

    kp = ak_htable_exclude_keypair_str( &ht, "key4" );
    printf("found: [key: %s, value: %s]\n", kp->data, kp->data + kp->key_length );
    ak_keypair_delete( kp );

   /* пытаемся получить доступ к удаленному ранее элементу */
    if(( kp = ak_htable_exclude_keypair_str( &ht, "key2" )) == NULL )
      printf("key2 not found\n");
     else {
       printf("key  %s, value: %s]\n", kp->data, kp->data + kp->key_length );
       ak_keypair_delete( kp );
     }

  /* выводим содержимое таблицы */
    printf(" таблица содержит %u списков\n", (unsigned int) ht.count );
    for( size_t i = 0; i < ht.count; i++ ) {
      ak_list list = &ht.list[i];
      cnt += list->count;
      if( list->count == 0 ) continue;
      printf(" - список: %2u содержит %u элементов\n",
                                                    (unsigned int) i, (unsigned int) list->count );
      ak_list_first( list );
      do{
         ak_keypair kp = (ak_keypair)list->current->data;
         printf("    - [key: %s, val: %s]\n", kp->data,
              ak_ptr_to_hexstr( kp->data + kp->key_length,  kp->value_length, ak_false ));
      }
       while( ak_list_next( list ));
    }
    printf(" таблица содержит %u элементов\n", (unsigned int) cnt );

  /* удаляем остатки пришеств */
   ak_htable_destroy( &ht );

 return EXIT_SUCCESS;
}
