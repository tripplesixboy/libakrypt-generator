/* --------------------------------------------------------------------------------- */
/* Пример example-g05n01.c                                                           */
/*                                                                                   */
/* --------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <libakrypt.h>

 int main( void )
{  /* значение исходной ключевой информации */
    ak_uint8 key[32] = {
      0x58, 0x16, 0x88, 0xD7, 0x6E, 0xFE, 0x12, 0x2B,
      0xB5, 0x5F, 0x62, 0xB3, 0x8E, 0xF0, 0x1B, 0xCC,
      0x8C, 0x88, 0xDB, 0x83, 0xE9, 0xEA, 0x4D, 0x55,
      0xD3, 0x89, 0x8C, 0x53, 0x72, 0x1F, 0xC3, 0x84 };
   /* какая-то переменная */
    int index = 0;

   /* массив для хранения производного ключа */
    ak_uint8 out[32];

   /* инициализируем библиотеку */
    ak_libakrypt_create( NULL );

   /* вырабатываем производный ключ с нескольких различных номеров ключей */
    for( index = 0; index < 261; index ++ ) {
       ak_skey_derive_tlstree( key, 32, index, tlstree_with_libakrypt_65536, out, 32 );
       printf("key[%03d]: %s\n", index, ak_ptr_to_hexstr( out, 32, ak_false ));
    }

    ak_libakrypt_destroy();
 return ( ak_error_get_value() == ak_error_ok ) ? EXIT_SUCCESS : EXIT_FAILURE;
}
