/* ----------------------------------------------------------------------------------------------- */
 #include <stdlib.h>
 #include <time.h>
 #include <string.h>
 #include <libakrypt.h>


 int main( void )
{
  ak_log_set_level( ak_log_maximum );
  ak_libakrypt_create( ak_function_log_stderr );
  ak_libakrypt_test_streebog256();
  ak_libakrypt_test_streebog512();
  ak_libakrypt_destroy();

 return EXIT_SUCCESS;
}
