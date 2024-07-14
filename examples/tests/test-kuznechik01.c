/* ----------------------------------------------------------------------------------------------- */
/*  тест развертки раундовых ключей */
 #include <stdio.h>
 #include <libakrypt.h>

/* ----------------------------------------------------------------------------------------------- */
 int main( void )
{
   /* тестовый ключ из ГОСТ Р 34.13-2015, приложение А.1
    ak_uint8 keyAnnexA[32] = {
      0xef,0xcd,0xab,0x89,0x67,0x45,0x23,0x01,0x10,0x32,0x54,0x76,0x98,0xba,0xdc,0xfe,
      0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88
    }; */

    ak_uint8 keyExample[32] = {
      0x49,0x45,0x20,0xce,0x26,0x51,0x8e,0xfd,0x7d,0x87,0x6d,0xd6,0xea,0xac,0x32,0x9e,
      0x81,0xb7,0x37,0x8a,0x9f,0xbc,0x0e,0xae,0x12,0x24,0x06,0x63,0x52,0x76,0xbe,0x72
    };

    int i, j = 0;
    struct bckey key;
    ak_uint64 *round = NULL;

   /* инициализируем библиотеку с максимальным уровнем аудита */
    ak_log_set_level( ak_log_maximum );
    ak_libakrypt_create( ak_function_log_stderr );

   /* создаем контекст секретного ключа */
    ak_bckey_create_kuznechik( &key );
   /* присваиваем значение, например так ak_bckey_set_key( &key, keyAnnexA, 32 ); */
    ak_bckey_set_key( &key, keyExample, 32 );

   /* выводим выработанные раундовые ключи */
    round =  (ak_uint64 *) key.key.data;
    printf("    15             9: 8             0\n--------------------------------------\n");
    for( i = 0, j = 1; i < 20; j++, i+=2 ) {
       printf("%2d| %016llx:%016llx\n", j, round[1+i]^round[41+i], round[i]^round[40+i] );
    }

   /* все уничтожаем */
    ak_bckey_destroy( &key );
    ak_libakrypt_destroy();

 return EXIT_SUCCESS;
}
