/* --------------------------------------------------------------------------------- */
/* Пример example-g06n01.c                                                           */
/* --------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <libakrypt.h>

 int main( void )
{
  struct hash ctx;
  ak_uint8 buffer[9] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39 };
  ak_uint64 crc64;

 /* устанавливаем уровень максимального аудита в стандартный поток ошибок */
  ak_log_set_level( ak_log_maximum );
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) {
   /* инициализация выполнена не успешно, следовательно, выходим из программы */
    ak_libakrypt_destroy();
    return EXIT_FAILURE;
  }

 /* создаем контекст */
  ak_hash_create_crc64( &ctx );

 /* вычисляем контрольную сумму */
  ak_hash_ptr( &ctx, buffer, sizeof( buffer ), &crc64, sizeof( crc64 ));

 /* выводим результат */
  printf("buffer: %s\n", ak_ptr_to_hexstr( buffer, sizeof( buffer ), ak_false ));
  printf("crc64:  %s [as array]\n", ak_ptr_to_hexstr( &crc64, sizeof( crc64 ), ak_false ));
  printf("crc64:  %016llx [as integer]\nresult: 6C40DF5F0B497347\n", crc64 );

 /* освобождаем память */
  ak_hash_destroy( &ctx );
  ak_libakrypt_destroy();

 return EXIT_SUCCESS;
}
