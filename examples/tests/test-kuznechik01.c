/* ----------------------------------------------------------------------------------------------- */
/*  тест развертки раундовых ключей */
 #include <stdio.h>
 #include <libakrypt.h>

/* ----------------------------------------------------------------------------------------------- */
 void print( ak_uint8 *data, int len, char *prefix )
{
    printf("\n%s:\n", prefix );
    printf("%s (%d -> 0)\n", ak_ptr_to_hexstr( data, len, ak_true ), len -1 );
    printf("%s (0 -> %d)\n", ak_ptr_to_hexstr( data, len, ak_false ), len -1);
}

/* ----------------------------------------------------------------------------------------------- */
 int first_test( ak_uint8 *key, ak_uint8 *input, int input_len, ak_uint8 *associated,
                         int associated_len, ak_uint8 *iv, int iv_len, ak_uint8 *calculated_icode )
{
    int i, j;
    struct bckey kc;
    ak_uint64 *round = NULL;
    ak_uint8 output[2048], icode[16];

    printf("---------------------------------------------------------------------------- %s\n",
                                                                                        __func__ );
    ak_bckey_create_kuznechik( &kc );
    ak_bckey_set_key( &kc, key, 32 ); /* присваиваем ключ и формируем раундовые ключи */

   /* выводим ключ */
    print( key, 32, "key");
   /* выводим выработанные раундовые ключи шифрования */
    round =  (ak_uint64 *) kc.key.data;
    printf("    15             9: 8             0\n--------------------------------------\n");
    for( i = 0, j = 1; i < 20; j++, i+=2 ) {
       printf("%2d| %016llx:%016llx\n", j, round[1+i]^round[41+i], round[i]^round[40+i] );
    }

   /* выводим входные данные */
    print( input, input_len, "plain");
    print( associated, associated_len, "associated");
    print( iv, iv_len, "iv");

   /* шифруем */
    memset( icode, 0, 16 );
    ak_bckey_encrypt_mgm( &kc, &kc, associated, associated_len, input, output, input_len,
                                                                           iv, iv_len, icode, 16 );

   /* выводим полученное */
    print( output, input_len, "encrypt");
    print( icode, 16, "icode");

    if( calculated_icode != NULL ) {
      if( !ak_ptr_is_equal_with_log( icode, calculated_icode, 16 )) {
        ak_error_message( ak_error_not_equal_data, __func__ ,
                                     "the value of integrity code for one kuznechik key is wrong" );
        return EXIT_FAILURE;
      } else printf("Ok\n");
    }

    ak_bckey_destroy( &kc );
  return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
 int second_test( ak_uint8 *key, ak_uint32 m, ak_uint32 fn, int mlen )
{
    int i = 0;
    ak_uint8 iv[16], a[32], data[2048];

   /* формируем iv */
    iv[ 0] = mlen&0xff;
    iv[ 1] = (ak_uint8)(mlen>>8);
    iv[ 2] = 0x00;
    iv[ 3] = 0x00;
    iv[ 4] = 0x00;
    iv[ 5] = 0x00;

    iv[ 6] = fn&0xff;
    iv[ 7] = (ak_uint8)(fn >>  8);
    iv[ 8] = (ak_uint8)(fn >> 16);
    iv[ 9] = (ak_uint8)(fn >> 24);
    iv[10] = m&0xff;
    iv[11] = (ak_uint8)(m>>8);
    iv[12] = 0x00;
    iv[13] = 0x2c;

    iv[14] = 0x00;
    iv[15] = 0x00;

   /* формируем ассоциированные данные */
    memset( a, 0, 32 );
    memcpy( a, iv, 16 );

   /* фомируем данные для шифрования,
      данные зависят от длины и формируются последовательным прибавлением единицы */
    memset( data, 0, mlen );
    for( i = 0; i < mlen; i++ ) data[i] = (ak_uint8)(i+1);

   /* шифруем */
  return first_test( key, data, mlen, a, 32, iv, 16, NULL );
}

/* ----------------------------------------------------------------------------------------------- */
 int main( void )
{
    int i, j;
    struct bckey kc;
    ak_uint64 *round = NULL;

   /* тестовый ключ из ГОСТ Р 34.13-2015, приложение А.1 */
    ak_uint8 keyAnnexA[32] = {
     0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
     0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88
    };

   /* инициализируем библиотеку */
    ak_libakrypt_create( ak_function_log_stderr );

   /* инициализируем ключ */
    ak_bckey_create_kuznechik( &kc );
    ak_bckey_set_key( &kc, keyAnnexA, 32 ); /* присваиваем ключ и формируем раундовые ключи */

   /* выводим выработанные раундовые ключи зашифрования */
    round =  (ak_uint64 *) kc.key.data;
    printf("    15             9: 8             0\n--------------------------------------\n");
    for( i = 0, j = 1; i < 20; j++, i+=2 ) {
       printf("%2d| %016llx:%016llx\n", j, round[1+i]^round[41+i], round[i]^round[40+i] );
    }

   /* уничтожаем ключи */
    ak_bckey_destroy( &kc );
    ak_libakrypt_destroy();

 return EXIT_SUCCESS;
}
