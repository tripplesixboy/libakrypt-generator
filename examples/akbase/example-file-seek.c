 #include <stdio.h>
 #include <libakrypt-base.h>

 int main( void )
{
    struct file fs;
    ak_uint8 buffer[16] = {
     0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };

   /* создаем файл */
    ak_file_create_to_write( &fs, "hello.seek" );
    ak_file_write( &fs, buffer, sizeof( buffer ));
    ak_file_close( &fs );

   /* теперь считываем в обратном порядке, используя lseek */
    ak_file_open_to_read( &fs, "hello.seek" );
    for( int offset = 15; offset >= 0; offset-- )
    {
        ak_file_lseek( &fs, offset, SEEK_SET );
        ak_file_read( &fs, buffer, 1 );
        printf("%02x ", buffer[0] );
    }
    printf("\n");
    ak_file_close( &fs );

 return EXIT_SUCCESS;
}
