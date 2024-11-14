/* ----------------------------------------------------------------------------------------------- */
 #include <stdlib.h>
 #include <libakrypt.h>

/* ----------------------------------------------------------------------------------------------- */
 int main( void )
{
    struct file fs;
    struct hash hctx;
    struct hmac hmac;
    struct bckey key;
    struct signkey skey;
    struct verifykey vkey;
    struct random generator;
    int exit_code = EXIT_SUCCESS;
    ak_uint8 data[8200], out[32], outf[32], outs[64];

   /* инициализируем систему аудита */
    ak_log_set_level( ak_log_maximum );
    ak_libakrypt_create( ak_function_log_stderr );

   /* создаем файл для экспериментов */
    for( size_t i = 0; i < sizeof( data ); i++ ) data[i] = (ak_uint8) i+1;
    ak_file_create_to_write( &fs, "hello.offset" );
    ak_file_write( &fs, data, sizeof( data ));
    ak_file_close( &fs );

   /* начинаем с хеширования */
    ak_hash_create_streebog256( &hctx );
    for( size_t i = 0; i < sizeof( data ); i++ )
    {
        ak_hash_ptr( &hctx, data, i, out, 32 );
        ak_hash_file_offset( &hctx, "hello.offset", 0, i, outf, 32 );
        if( !ak_ptr_is_equal_with_log( out, outf, 32 )) {
           printf("hash = %2d No (start)\n", (int) i );
           exit_code = EXIT_FAILURE;
        }

        ak_hash_ptr( &hctx, data +i, sizeof( data ) -i, out, 32 );
        ak_hash_ptr( &hctx, data +i, sizeof( data ) -i, out, 32 );
        ak_hash_file_offset( &hctx, "hello.offset", i, -1, outf, 32 );
        if( !ak_ptr_is_equal_with_log( out, outf, 32 )) {
           printf("hash = %2d No (end)\n", (int) i );
           exit_code = EXIT_FAILURE;
         }

         ak_hash_ptr( &hctx, data +i, ak_min( 10, sizeof( data ) -i ), out, 32 );
         ak_hash_file_offset( &hctx, "hello.offset", i, 10, outf, 32 );
         if( !ak_ptr_is_equal_with_log( out, outf, 32 )) {
            printf("hash = %2d No (middle)\n", (int) i );
            exit_code = EXIT_FAILURE;
         }
    }
    ak_hash_destroy( &hctx );
    if( exit_code == EXIT_SUCCESS ) printf("hash Ok\n");
     else {
       printf("hash Wrong\n");
       goto labex;
     }

   /* далее hmac */
    ak_hmac_create_streebog256( &hmac );
    ak_hmac_set_key_from_password( &hmac, "password", 8, "salt", 4 );
    for( size_t i = 0; i < sizeof( data ); i++ )
    {
        ak_hmac_ptr( &hmac, data, i, out, 32 );
        ak_hmac_file_offset( &hmac, "hello.offset", 0, i, outf, 32 );
        if( !ak_ptr_is_equal_with_log( out, outf, 32 )) {
           printf("hmac = %2d No (start)\n", (int) i );
           exit_code = EXIT_FAILURE;
         }

        ak_hmac_ptr( &hmac, data +i, sizeof( data ) -i, out, 32 );
        ak_hmac_file_offset( &hmac, "hello.offset", i, -1, outf, 32 );
        if( !ak_ptr_is_equal_with_log( out, outf, 32 )) {
           printf("hmac = %2d No (end)\n", (int) i );
           exit_code = EXIT_FAILURE;
         }

        ak_hmac_ptr( &hmac, data +i, ak_min( 10, sizeof( data ) -i), out, 32 );
        ak_hmac_file_offset( &hmac, "hello.offset", i, 10, outf, 32 );
        if( !ak_ptr_is_equal_with_log( out, outf, 32 )) {
           printf("hmac = %2d No (middle)\n", (int) i );
           exit_code = EXIT_FAILURE;
         }
    }
    ak_hmac_destroy( &hmac );
    if( exit_code == EXIT_SUCCESS ) printf("hmac Ok\n");
     else {
       printf("hmac Wrong\n");
       goto labex;
     }

   /* в заключение, cmac */
    ak_bckey_create_kuznechik( &key );
    ak_bckey_set_key_from_password( &key, "password", 8, "salt", 4 );
    for( size_t i = 0; i < sizeof( data ); i++ )
    {
       memset( out, 0, sizeof( out ));
       memset( outf, 0, sizeof( outf ));
        ak_bckey_cmac( &key, data, i, out, key.bsize );
        ak_bckey_cmac_file_offset( &key, "hello.offset", 0, i, outf, key.bsize );
        if( !ak_ptr_is_equal_with_log( out, outf, key.bsize )) {
           printf("cmac = %2d No (start)\n", (int) i );
           exit_code = EXIT_FAILURE;
         }

        ak_bckey_cmac( &key, data +i, sizeof( data ) -i, out, key.bsize );
        ak_bckey_cmac_file_offset( &key, "hello.offset", i, -1, outf, key.bsize );
        if( !ak_ptr_is_equal_with_log( out, outf, key.bsize )) {
           printf("cmac = %2d No (end)\n", (int) i );
           exit_code = EXIT_FAILURE;
         }

        ak_bckey_cmac( &key, data +i, ak_min( 10, sizeof( data ) -i), out, key.bsize );
        ak_bckey_cmac_file_offset( &key, "hello.offset", i, 10, outf, key.bsize );
        if( !ak_ptr_is_equal_with_log( out, outf, key.bsize )) {
           printf("cmac = %2d No (middle)\n", (int) i );
           exit_code = EXIT_FAILURE;
         }
    }
    ak_bckey_destroy( &key );
    if( exit_code == EXIT_SUCCESS ) printf("cmac Ok\n");
     else {
       printf("cmac Wrong\n");
       goto labex;
     }

   /* последний фрагмент снова про хеш, но теперь в свете электронной подписи */
    ak_random_create_hrng( &generator );
    ak_signkey_create_streebog256( &skey );
    ak_signkey_set_key_random( &skey, &generator );
    ak_verifykey_create_from_signkey( &vkey, &skey );

    for( size_t i = 4000; i < 5000; i++ )
    {
       /* подписываем память, проверяем файл */
        ak_signkey_sign_ptr( &skey, &generator, data, i, outs, 64 );
        if( ak_verifykey_verify_file_offset( &vkey, "hello.offset", 0, (int) i, outs ) != ak_true ) {
           printf("sign = %2d No (verify file, start)\n", (int) i );
           exit_code = EXIT_FAILURE;
        }
       /* и наоборот, подписываепм файл - проверяем память */
        ak_signkey_sign_file_offset( &skey, &generator, "hello.offset", 0, (int) i, outs, 64 );
        if( ak_verifykey_verify_ptr( &vkey, data, i, outs ) != ak_true ) {
           printf("sign = %2d No (verify ptr, start)\n", (int) i );
           exit_code = EXIT_FAILURE;
        }
    }
    ak_verifykey_destroy( &vkey );
    ak_signkey_destroy( &skey );
    ak_random_destroy( &generator );
    if( exit_code == EXIT_SUCCESS ) printf("sign Ok\n");
     else {
       printf("sign Wrong\n");
       goto labex;
     }

    labex:
    ak_libakrypt_destroy();

  return exit_code;
}

/* ----------------------------------------------------------------------------------------------- */
