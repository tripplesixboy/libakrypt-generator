/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014, 2023 by Axel Kenzo, axelkenzo@mail.ru                                      */
/*                                                                                                 */
/*  Файл ak_buffer.с                                                                               */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt-base.h>

/* ----------------------------------------------------------------------------------------------- */
/*! Функция присваивает структуре buffer указатель на данные.
 *  Буфер не владеет присвоенными данными, поэтому вопросы о последующей очистке и удалении данных
 *  находятся вне его компетенции.
 *
 *  @param buffer указатель на структуру буфера
 *  @param ptr указатель на данные
 *  @param size размер данных (в байтах)
 *  @return В случае успеха функция возвращает ноль.
 *  В случае возникновения ошибки возвращается ее код.                                             */
/* ----------------------------------------------------------------------------------------------- */
 int ak_buffer_set_ptr( ak_buffer buffer, ak_uint8 *ptr, const size_t size )
{
   /* сначала удаляем старое */
    if( ak_buffer_destroy( buffer ) != ak_error_ok ) return ak_error_null_pointer;

   /* присваиваем указатели */
    if(( buffer->ptr = ptr ) == NULL ) buffer->size = 0;
      else buffer->size = size;

    buffer->is_allocated = ak_false;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция выделяет область в оперативной памяти и копирует туда переданные пользователем данные.
 *  Если данные были ранее размещены в буфере, то они удаляются.
 *
 *  @param buffer указатель на структуру буфера
 *  @param ptr указатель на данные
 *  @param size размер данных (в байтах)
 *  @return В случае успеха функция возвращает ноль.
 *  В случае возникновения ошибки возвращается ее код.                                             */
/* ----------------------------------------------------------------------------------------------- */
 int ak_buffer_alloc_ptr( ak_buffer buffer, const ak_uint8 *ptr, const size_t size )
{
   /* сначала удаляем старое */
    if( ak_buffer_destroy( buffer ) != ak_error_ok ) return ak_error_null_pointer;

   /* присваиваем указатели */
    if (( ptr  == NULL ) || ( size == 0 )) {
      buffer->ptr = NULL;
      buffer->size = 0;
      buffer->is_allocated = ak_false;
    }
     else {
      /* при выделении добавляем лишний ноль в конце */
       if(( buffer->ptr = malloc( size +1 )) == NULL )
         return ak_error_message( ak_error_out_of_memory, __func__, "memory allocation error" );

      /* копируем данные */
       buffer->ptr[size] = 0;
       memcpy( buffer->ptr, ptr, size );
       buffer->size = size;
       buffer->is_allocated = ak_true;
     }

  return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param buffer указатель на структуру буфера
 *  @return В случае успеха функция возвращает ноль.
 *  В случае возникновения ошибки возвращается ее код.                                             */
/* ----------------------------------------------------------------------------------------------- */
 int ak_buffer_destroy( ak_buffer buffer )
{
    if( buffer == NULL )
      return ak_error_message( ak_error_null_pointer, __func__, "using null-pointer to buffer" );

    if( buffer->is_allocated ) free( buffer->ptr );
    buffer->ptr = NULL;
    buffer->size = 0;
    buffer->is_allocated = ak_false;

  return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                    ak_buffer.c  */
/* ----------------------------------------------------------------------------------------------- */
