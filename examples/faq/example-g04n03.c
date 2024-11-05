/* --------------------------------------------------------------------------------- */
/* Пример example-g04n03.c                                                           */
/* Иллюстрация проверки качества двоичной последовательности, вырабатываемой ПДСЧ    */
/* --------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <libakrypt.h>

 int main( void )
{
 /* буффер для хранения случайных данных */
  ak_uint8 buffer[64];

 /* определяем контекст генератора псевдослучайных значений */
  struct random generator;

 /* устанавливаем уровень аудита */
  ak_log_set_level( ak_log_maximum );
  ak_libakrypt_create( ak_function_log_stderr );

 /* вызываем конструктор генератора и вырабатываем случайные данные */
  ak_random_create_hrng( &generator );

  for( int i = 0; i < 1; i++ )
  {
      ak_random_ptr( &generator, buffer, 64 );

      printf("%s ", ak_ptr_to_hexstr( buffer, 64, ak_false ));
      if( ak_random_dynamic_test( buffer, 64 )) printf("Ok\n");
       else { /* в момент, когда тест не выполнен, производится остановка программы */
        printf("No [number: %d]\n", i );
        break;
       }
  }
 /* вызываем деструктор генератора */
  ak_random_destroy( &generator );
  ak_libakrypt_destroy();




 return EXIT_SUCCESS;
}
