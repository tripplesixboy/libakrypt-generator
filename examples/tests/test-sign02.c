/* Пример показывает простейшую процедуру электроной подписи.

   test-sign01.c
*/
 #include <time.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <libakrypt.h>

 int main( void )
{
  ak_oid oid = NULL;
  struct signkey sk;
  struct verifykey vk;
  struct random generator;
  int result = EXIT_FAILURE;
  ak_uint8 sign[128];

 /* тестовое значение ключа */
  ak_uint8 testkey[64] = {
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x27, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x28,
    0xbc, 0xd6, 0xd3, 0xf7, 0x46, 0xb6, 0x31, 0xdf, 0x92, 0x80, 0x14, 0xf6, 0xc5, 0xbf, 0x9c, 0x40,
    0x41, 0xaa, 0x28, 0xd2, 0xf1, 0xab, 0x14, 0x82, 0x80, 0xcd, 0x9e, 0xd5, 0x6f, 0xed, 0xa4, 0x19 };
 /* тестовое значение хеш-кода */
  ak_uint8 testhash[64] = {
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x27, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x27, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0x7a, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x28,
    0x7b, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x28 };


 /* инициализируем библиотеку */
  ak_log_set_level( ak_log_maximum );
  if( !ak_libakrypt_create( ak_function_log_stderr )) return result;

 /* создаем генератор псевдослучайных последовательностей */
  if( ak_random_create_lcg( &generator ) != ak_error_ok ) goto labex;

 /* перебираем oid-ы всех кривых и тестируем для каждой */
  oid = ak_oid_find_by_mode( wcurve_params );
  do {
       char filename[128];
       ak_wcurve wc = oid->data;
       size_t length = sizeof( ak_uint64 )*wc->size;

      /* создаем структуру секретного ключа */
       switch( wc->size ) {
         case ak_mpzn256_size: ak_signkey_create_streebog256( &sk ); break;
         case ak_mpzn512_size: ak_signkey_create_streebog512( &sk ); break;
       }

      /* установили ключ */
       ak_signkey_set_curve( &sk, oid->data );
       ak_signkey_set_key( &sk, testkey, length );

      /* выработали подпись */
       ak_signkey_sign_hash( &sk, &generator, testhash, length, sign, 2*length );

      /* выработали открытый ключ и сохранили его */
       ak_verifykey_create_from_signkey( &vk, &sk );
       ak_snprintf( filename, sizeof( filename ), "test.%s.pub",
                                                               ak_oid_find_by_data( wc )->name[0] );
       ak_verifykey_export_to_file( &vk, filename );

      /* очистили всю память */
       ak_signkey_destroy( &sk );
       ak_verifykey_destroy( &vk );
       memset( &vk, 0, sizeof( struct verifykey ));

      /* теперь считываем открытый ключ из файла */
       ak_verifykey_create_from_file( &vk, filename );

       printf("public key (%s):\nx = %s\n", filename,
                          ak_ptr_to_hexstr( vk.qpoint.x, sizeof(ak_uint64)*vk.wc->size, ak_false ));
       printf("y = %s\n\n",
                          ak_ptr_to_hexstr( vk.qpoint.y, sizeof(ak_uint64)*vk.wc->size, ak_false ));
      /* проверяем подпись */
       if( ak_verifykey_verify_hash( &vk, testhash, length, sign ) != ak_true ) {
         ak_verifykey_destroy( &vk );
         printf("wrong sign!!\n");
         return result;
       }

      /* окончательно уничтожаем ключ */
       ak_verifykey_destroy( &vk );

  } while(( oid = ak_oid_findnext_by_mode( oid, wcurve_params )) != NULL );

  result = EXIT_SUCCESS;
  labex:
    ak_libakrypt_destroy();

 return result;
}
