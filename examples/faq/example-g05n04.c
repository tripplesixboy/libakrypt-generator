/* --------------------------------------------------------------------------------- */
/* Файл example-g05n04.c                                                             */
/* Пример иллюстрирует вызовы функций выработки производного ключа kdf256 и kdf512   */
/* --------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <libakrypt.h>

 int main( void )
{
    int error = ak_error_ok;

   /* значение исходной ключевой информации */
    ak_uint8 key[32] = {
     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
     0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

   /* ожидаемое значение для ключа алгоритма kdf256 */
    ak_uint8 outkey32[32] = {
     0xa1, 0xaa, 0x5f, 0x7d, 0xe4, 0x02, 0xd7, 0xb3,
     0xd3, 0x23, 0xf2, 0x99, 0x1c, 0x8d, 0x45, 0x34,
     0x01, 0x31, 0x37, 0x01, 0x0a, 0x83, 0x75, 0x4f,
     0xd0, 0xaf, 0x6d, 0x7c, 0xd4, 0x92, 0x2e, 0xd9 };

   /* ожидаемое значение для ключа алгоритма kdfnmac */
    ak_uint8 outkey32nmac[32] = {
     0x6b, 0x00, 0x0f, 0x34, 0xef, 0x6f, 0xa2, 0x52,
     0x48, 0xee, 0x1a, 0xd6, 0x34, 0x4e, 0x7c, 0xe2,
     0x41, 0x23, 0x11, 0x3f, 0xb1, 0xeb, 0xf1, 0x7a,
     0xce, 0x0a, 0xff, 0x72, 0x8f, 0x30, 0x3d, 0x82 };

   /* ожидаемое значение для ключа алгоритма kdf512 */
    ak_uint8 outkey64[64] = {
     0xa5, 0x9b, 0xab, 0x22, 0xec, 0xae, 0x19, 0xc6,
     0x5f, 0xbd, 0xe6, 0xe5, 0xf4, 0xe9, 0xf5, 0xd8,
     0x54, 0x9d, 0x31, 0xf0, 0x37, 0xf9, 0xdf, 0x9b,
     0x90, 0x55, 0x00, 0xe1, 0x71, 0x92, 0x3a, 0x77,
     0x3d, 0x5f, 0x15, 0x30, 0xf2, 0xed, 0x7e, 0x96,
     0x4c, 0xb2, 0xee, 0xdc, 0x29, 0xe9, 0xad, 0x2f,
     0x3a, 0xfe, 0x93, 0xb2, 0x81, 0x4f, 0x79, 0xf5,
     0x00, 0x0f, 0xfc, 0x03, 0x66, 0xc2, 0x51, 0xe6 };

   /* массивы данных, используемые для выработки/индексации производного ключа */
    ak_uint8 label[4] = { 0x26, 0xbd, 0xb8, 0x78 };
    ak_uint8 seed[8] = { 0xaf, 0x21, 0x43, 0x41, 0x45, 0x65, 0x63, 0x78 };

   /* область памяти для полученных результатов */
    ak_uint8 out32[32], out64[64];

   /* контекст секретного ключа длиной 256 бит */
    struct bckey ctx;

   /* инициализруем библиотеку */
    ak_log_set_level( ak_log_maximum );
    ak_libakrypt_create( ak_function_log_stderr );


   /* итерация первая: прямое применение функций к массивам данных */
   /* вырабатываем производный ключ с помощью алгоритма kdf256
      и проверяем, что его значение совпало с ожидаемым */
    if(( error = ak_skey_derive_kdf_hmac( hmac_hmac256_kdf,
                        key, sizeof( key ), label, sizeof( label ),
                        seed, sizeof( seed ), out32, sizeof( out32 ))) != ak_error_ok ) goto exlab;

    if( !ak_ptr_is_equal_with_log( out32, outkey32, sizeof( outkey32 ))) {
      error = ak_error_message( ak_error_not_equal_data, __func__,
                                                        "incorrect value of derived 256 bit key" );
      goto exlab1;
    }

   /* вырабатываем производный ключ с помощью алгоритма kdfnmac
      и проверяем, что его значение совпало с ожидаемым */
    if(( error = ak_skey_derive_kdf_hmac( hmac_nmac_kdf,
                        key, sizeof( key ), label, sizeof( label ),
                        seed, sizeof( seed ), out32, sizeof( out32 ))) != ak_error_ok ) goto exlab;

    if( !ak_ptr_is_equal_with_log( out32, outkey32nmac, sizeof( outkey32nmac ))) {
      error = ak_error_message( ak_error_not_equal_data, __func__,
                                                  "incorrect value of derived 256 bit key (mac)" );
      goto exlab1;
    }

   /* вырабатываем производный ключ с помощью алгоритма kdf512
      и проверяем, что его значение совпало с ожидаемым */
    if(( error = ak_skey_derive_kdf_hmac( hmac_hmac512_kdf,
                        key, sizeof( key ), label, sizeof( label ),
                        seed, sizeof( seed ), out64, sizeof( out64 ))) != ak_error_ok ) goto exlab;

    if( !ak_ptr_is_equal_with_log( out64, outkey64, 64 )) {
      error = ak_error_message( ak_error_not_equal_data, __func__,
                                                        "incorrect value of derived 512 bit key" );
      goto exlab1;
    }

   /* итерация вторая: применение функций к контексту секретного ключа */
   /* в начале, создаем контекст и присваиваем ему тоже самое, константное значение */
    ak_bckey_create_magma( &ctx );
    ak_bckey_set_key( &ctx, key, sizeof( key ));

   /* вырабатываем производный ключ с помощью алгоритма kdf256
      и проверяем, что его значение совпало с ожидаемым */
    memset( out32, 0, sizeof( out32 ));
    if(( error = ak_skey_derive_kdf_hmac_from_skey( hmac_hmac256_kdf,
                        &ctx, label, sizeof( label ),
                        seed, sizeof( seed ), out32, sizeof( out32 ))) != ak_error_ok ) goto exlab;

    if( !ak_ptr_is_equal_with_log( out32, outkey32, 32 )) {
      error = ak_error_message( ak_error_not_equal_data, __func__,
                                                        "incorrect value of derived 256 bit key" );
      goto exlab;
    }

   /* вырабатываем производный ключ с помощью алгоритма kdfnmac
      и проверяем, что его значение совпало с ожидаемым */
    memset( out32, 0, sizeof( out32 ));
    if(( error = ak_skey_derive_kdf_hmac_from_skey( hmac_nmac_kdf,
                        &ctx, label, sizeof( label ),
                        seed, sizeof( seed ), out32, sizeof( out32 ))) != ak_error_ok ) goto exlab;

    if( !ak_ptr_is_equal_with_log( out32, outkey32nmac, 32 )) {
      error = ak_error_message( ak_error_not_equal_data, __func__,
                                                 "incorrect value of derived 256 bit key (nmac)" );
      goto exlab;
    }

   /* вырабатываем производный ключ с помощью алгоритма kdf512
      и проверяем, что его значение совпало с ожидаемым */
    memset( out64, 0, sizeof( out64 ));
    if(( error = ak_skey_derive_kdf_hmac_from_skey( hmac_hmac512_kdf,
                        &ctx, label, sizeof( label ),
                        seed, sizeof( seed ), out64, sizeof( out64 ))) != ak_error_ok ) goto exlab;

    if( !ak_ptr_is_equal_with_log( out64, outkey64, 64 )) {
      error = ak_error_message( ak_error_not_equal_data, __func__,
                                                        "incorrect value of derived 256 bit key" );
      goto exlab;
    }

   /* итерация третья: выработка новых контекстов секретного ключа */




   /* завершаем работу с криптографическими преобразованиями */
    exlab:
     ak_bckey_destroy( &ctx );
    exlab1:
    ak_libakrypt_destroy();

  return ( error == ak_error_ok ) ? EXIT_SUCCESS : EXIT_FAILURE;
}
