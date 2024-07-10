/* ----------------------------------------------------------------------------------------------- */
 #include <stdlib.h>
 #include <time.h>
 #include <string.h>
 #include <libakrypt.h>


 int main( void )
{
  char *datastr = "ab2328d9ee6f3dbfec908c5a817ccf116be667345d877f9264cbb2d3d34d633636363636363636363636363636363636363636363636363636363636363636360000000000000000000000000000000000000000000000000000000001000000";
  ak_uint8 data[96], out[32];
  struct hash ctx;

  ak_log_set_level( ak_log_none );
  ak_libakrypt_create( ak_function_log_stderr );

 /* первый тест */
  ak_hexstr_to_ptr( datastr, data, 96, ak_false );
  printf("Исходный вектор:\n%s\n", ak_ptr_to_hexstr( data, 96, ak_false ));

  ak_hash_create_streebog256( &ctx );
  ak_hash_ptr( &ctx, data, 96, out, 32 );
  ak_hash_destroy( &ctx );

  printf("Хэш-значение:\n%s", ak_ptr_to_hexstr( out, 32, ak_false ));
  ak_libakrypt_destroy();

  if( strncmp( ak_ptr_to_hexstr( out, 32, ak_false ),
                    "283d8516e0a835b1b21dd35cee564baacb99ded56b9c5f528b7a3c9f79925508", 64 ) == 0 )
    {
      printf(" Ok\n");
      return EXIT_SUCCESS;
    }

  printf(" No\n");
  return EXIT_FAILURE;
}
