/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2019 - 2023 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_kdf.с                                                                                  */
/*  - содержит реализацию функций выработки производных ключей                                     */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt-internal.h>

/* ----------------------------------------------------------------------------------------------- */
#ifdef AK_HAVE_STDLIB_H
 #include <stdlib.h>
#else
 #error Library cannot be compiled without stdlib.h header
#endif
#ifdef AK_HAVE_STRING_H
 #include <string.h>
#else
 #error Library cannot be compiled without string.h header
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! Для генерации ключа используется алгоритм KDF_GOSTR3411_2012_256.
    Вырабатываемый ключ `K` имеет длину 256 бит и определяется равенством

 \code
   K = KDF256( Kin, label, seed ) = HMAC256( Kin, 0x01 || label || 0x00 || seed || 0x01 || 0x00 )
 \endcode

    \param master_key Указатель на корректно созданный ранее контекст секретного ключа `Kin`.
    В качестве типов криптографических механизмов для данного ключа
    допускаются блочные шифры и ключи выработки hmac.
    Использование ключей с другим установленным значением типа механихма приводит к ошибке.
    \param label Используемая в алгоритме метка производного ключа
    \param label_size Длина метки (в октетах)
    \param seed Используемое в алгоритме инициализирующее значение
    \param seed_size Длина инициализирующего значения (в октетах)
    \param out Указатель на область памяти, в которую помещается выработанное значение
     (память в размере 32 октета должна быть выделена заранее)
    \param size Размер выделенной памяти

    \return В случае возникновения ошибки функция возвращает ее код. В случае успеха
    возвращается \ref ak_error_ok (ноль).                                                          */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_derive_kdf256_to_ptr( ak_pointer master_key, ak_uint8* label, const size_t label_size,
                           ak_uint8* seed, const size_t seed_size, ak_uint8 *out, const size_t size )
{
  int error = ak_error_ok;
  struct hmac ictx, *pctx = NULL;
  ak_uint8 cv[2] = { 0x01, 0x00 };
  ak_skey master = (ak_skey)master_key;

  if( master_key == NULL )  return ak_error_message( ak_error_null_pointer, __func__,
                                                              "using null pointer to master key" );
  if(( label == NULL ) && ( seed == NULL ))
    return ak_error_message( ak_error_null_pointer, __func__,
                                                "using null pointer to both input data pointers" );
  if(( label_size == 0 ) && ( seed_size == 0 ))
    return ak_error_message( ak_error_null_pointer, __func__,
                                                "using zero length for both input data pointers" );
 /* проверяем, что мастер-ключ установлен */
  if( master->oid->mode != algorithm )
    return ak_error_message( ak_error_oid_mode, __func__,
                                   "using the master key which is not a cryptographic algorithm" );
  switch( master->oid->engine ) {
    case block_cipher:
    case hmac_function:
      break;
    default: return ak_error_message_fmt( ak_error_oid_engine, __func__,
                                              "using the master key with unsupported engine (%s)",
                                              ak_libakrypt_get_engine_name( master->oid->engine ));
  }

  if(( master->flags&key_flag_set_key ) == 0 )
    return ak_error_message( ak_error_key_value, __func__,
                                                     "using the master key with undefined value" );
  /* целостность ключа */
  if( master->check_icode( master ) != ak_true )
    return ak_error_message( ak_error_wrong_key_icode,
                                              __func__, "incorrect integrity code of master key" );

 /* если входящий контекст - hmac - используем его, в противном случае создаем новый */
  if( master->oid->engine == hmac_function ) {
    pctx = master_key;
  }
   else {
    /* создаем контект, который будет использован для генерации ключа */
     if(( error = ak_hmac_create_streebog256( &ictx )) != ak_error_ok )
       return ak_error_message( error, __func__, "incorrect creation of intermac hmac context" );
    /* присваиваем указатель */
     pctx = &ictx;
    /* копируем значение исходного ключа */
     master->unmask( master );
     error = ak_hmac_set_key( pctx, master->key, master->key_size );
     master->set_mask( master );
     if( error != ak_error_ok ) {
       ak_error_message( error, __func__, "incorrect assigning a master key value" );
       goto labex;
     }
   }

 /* только теперь приступаем к выработке нового ключевого значения */
  ak_hmac_clean( pctx );
  ak_hmac_update( pctx, cv, 1 );
  if(( label != NULL ) && ( label_size != 0 )) ak_hmac_update( pctx, label, label_size );
  ak_hmac_update( pctx, cv+1, 1 );
  if(( seed != NULL ) && ( seed_size != 0 )) ak_hmac_update( pctx, seed, seed_size );
  error = ak_hmac_finalize( pctx, cv, 2, out, size );

  labex:
   if( pctx == &ictx ) ak_hmac_destroy( &ictx); /* удаляем свое, чужое не трогаем */
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Для генерации ключа используется алгоритм KDF_GOSTR3411_2012_256.
    Вырабатываемый ключ `K` имеет длину 256 бит и определяется равенством

 \code
   K = KDF256( Kin, label, seed ) = HMAC256( Kin, 0x01 || label || 0x00 || seed || 0x01 || 0x00 )
 \endcode

    В процессе выполнения функция выделяет в памяти область для нового ключа,
    инициализирует его и присваивает выработанное значение, а также устанавливает ресурс ключа.

    \param oid Идентификатор создаваемого ключа
    \param master_key Указатель на корректно созданный ранее контекст секретного ключа `Kin`.
    В качестве типов криптографических механизмов для данного ключа
    допускаются блочные шифры и ключи выработки hmac.
    Использование ключей с другим установленным значением типа механихма приводит к ошибке.
    \param label Используемая в алгоритме метка производного ключа
    \param label_size Длина метки (в октетах)
    \param seed Используемое в алгоритме инициализирующее значение
    \param seed_size Длина инициализирующего значения (в октетах)

    \return В случае возникновения ошибки функция возвращает NULL, а код может быть
    получен с помощью функции ak_error_get_value(). В случае успеха
    возвращает указатель на созданый контекст секретного ключа.                                    */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_skey_new_derive_kdf256( ak_oid oid, ak_pointer master_key,
                ak_uint8* label, const size_t label_size, ak_uint8* seed, const size_t seed_size )
{
  ak_uint8 out[32]; /* размер 32 определяется используемым алгоритмом kdf256 */
  int error = ak_error_ok;
  ak_pointer handle = NULL;

 /* выполняем проверки */
  if( oid == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to oid context" );
    return NULL;
  }
  if( oid->func.first.set_key == NULL ) {
    ak_error_message_fmt( ak_error_undefined_function, __func__,
                                       "using oid (%s) with unsupported key assigning mechanism" );
    return NULL;
  }

 /* создаем производный ключ */
  if(( error = ak_skey_derive_kdf256_to_ptr( master_key,
                                 label, label_size, seed, seed_size, out, 32 )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect generation of derivative key" );
    goto labex;
  }

 /* погружаем данные в контекст */
  if(( handle = ak_oid_new_object( oid )) == NULL ) {
    ak_error_message( error = ak_error_get_value(), __func__,
                                                  "incorrect creation of new secret key context" );
    goto labex;
  }
  if(( error = oid->func.first.set_key( handle, out, 32 )) != ak_error_ok ) {
   ak_error_message( error, __func__, "incorrect assigning a derivative key value" );
   goto labex;
  }

 /* очищаем память */
  labex:
    if( error != ak_error_ok ) handle = ak_oid_delete_object( oid, handle );
    ak_ptr_wipe( out, sizeof( out ), &((ak_skey)master_key)->generator );

 return handle;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @return В случае успеха, функция возвращает истину. В случае возникновения ошибки,
 *  возвращается ложь. Код ошибки может быть получен с помощью вызова функции ak_error_get_value() */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_libakrypt_test_kdf256( void )
{
   /* входной ключ */
    ak_uint8 static_input_key[32] = {
     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
   /* выходной ключ */
    ak_uint8 static_output_key[32] = {
     0xa1, 0xaa, 0x5f, 0x7d, 0xe4, 0x02, 0xd7, 0xb3, 0xd3, 0x23, 0xf2, 0x99, 0x1c, 0x8d, 0x45, 0x34,
     0x01, 0x31, 0x37, 0x01, 0x0a, 0x83, 0x75, 0x4f, 0xd0, 0xaf, 0x6d, 0x7c, 0xd4, 0x92, 0x2e, 0xd9
    };

    ak_uint8 out[32];
    int error = ak_error_ok;
    ak_uint8 static_label[4] = { 0x26, 0xbd, 0xb8, 0x78 };
    ak_uint8 static_seed[8] = { 0xaf, 0x21, 0x43, 0x41, 0x45, 0x65, 0x63, 0x78 };

   /* структура временного ключа */
    struct bckey sk;

   /* инициализируем контекст секретного ключа для блочного шифра */
    if(( error = ak_bckey_create_magma( &sk )) != ak_error_ok ) {
      ak_error_message( error, __func__, "incorrect creation of block cipher context");
      return ak_false;
    }
    if(( error = ak_bckey_set_key( &sk, static_input_key,
                                                     sizeof( static_input_key ))) != ak_error_ok ) {
      ak_error_message( error, __func__, "incorrect assignin' of new secret key value");
      goto exlab;
    }

   /* вычисляем производный ключ и сравниваем результат */
    memset( out, 0, 32 );
    if(( error = ak_skey_derive_kdf256_to_ptr( &sk,
                                  static_label,
                                  sizeof( static_label ),
                                  static_seed,
                                  sizeof( static_seed ),
                                  out, /* сюда помещаем результат вычислений */
                                  sizeof( out ))) != ak_error_ok ) {
      ak_error_message( error, __func__, "incorrect generation of a new secret key value");
      goto exlab;
    }

   /* сравниваем вычисленный вектор с изначально заданным */
    if( !ak_ptr_is_equal_with_log( out, static_output_key, sizeof( static_output_key ))) {
      ak_error_message( error = ak_error_not_equal_data, __func__,
                                         "the value of kdf_gostr3411_2012_256 function is wrong ");
    }
     else {
        if( ak_log_get_level() >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                       "the test for kdf-gostr3411-2012-256 function from R 50.1.113-2016 is Ok" );
     }

    exlab:
      ak_ptr_wipe( out, 32, &sk.key.generator );
      ak_bckey_destroy( &sk );

 return ( error == ak_error_ok ) ? ak_true : ak_false;
}

/* ----------------------------------------------------------------------------------------------- */
             /* Реализация функций генерации ключей согласно Р 1323565.1.022-2018 */
/* ----------------------------------------------------------------------------------------------- */
 #define ak_uint64_to_ptr( x, ptr ) { \
                                      ptr[0] = ( x >> 56 )&0xFF; \
                                      ptr[1] = ( x >> 48 )&0xFF; \
                                      ptr[2] = ( x >> 40 )&0xFF; \
                                      ptr[3] = ( x >> 32 )&0xFF; \
                                      ptr[4] = ( x >> 24 )&0xFF; \
                                      ptr[5] = ( x >> 16 )&0xFF; \
                                      ptr[6] = ( x >>  8 )&0xFF; \
                                      ptr[7] = x&0xFF;           \
                                    }
 #define ak_ptr_to_uint64( ptr, x ) { \
                                     x = ptr[0]; x <<= 8;\
                                     x += ptr[1]; x <<= 8;\
                                     x += ptr[2]; x <<= 8;\
                                     x += ptr[3]; x <<= 8;\
                                     x += ptr[4]; x <<= 8;\
                                     x += ptr[5]; x <<= 8;\
                                     x += ptr[6]; x <<= 8;\
                                     x += ptr[7]; \
                                    }
/* ----------------------------------------------------------------------------------------------- */
/*! Функция вырабатывает промежуточный ключ `K*` и устанавливает начальное состояние
    строки `format`, используемых в дальнейшем для выработки ключевой последовательности.
    Промежуточный ключ `K*` определяется одним из следующих равенств.

 \code
                             NMAC256( seed, Kin )
    K* = KDF1( seed, Kin ) = LSB256( HMAC512( seed, Kin ))
                             seed \oplus Kin, если len(seed) = len(Kin) = 256 (в битах)
 \endcode

    Значение последовательности октетов `format` определяется следующим образом.

 \code
    format = Ki-1 || i || label || L,
 \endcode
   где
   - длина `Ki-1` определяется младшими четырьмя битами типа kdf_t и может принимать
     значения 8, 16, 32 и 64 октетов,
   - длина kdf равна 1 октет,
   - длина i равна 4 октетам (запись целого числа производится в big-endian кодировке),
   - длина поля label определяется значением label_size,
   - длина поля L равна 4 октетам (запись целого числа производится в big-endian кодировке).

    Далее, с помощью промежуточного ключа вырабатывается ключевая информация,
    представленная в виде последовательности блоков `K1`, `K2`, ..., `Kn`.
    Для вычисления указаных блоков используются следующие соотношения.

 \code
    K0 = IV,

    Ki = Mac( K*, Ki-1 || i || label || L ), где L = n*len(Ki) и

    K = K1 || K2 || ... || Kn
 \endcode

   В качестве функции `Mac` могут выступать функции cmac (magma,kuznechik), hmac(512,256), nmac(streebog).
   Согласно Р 1323565.1.022-2018, может быть реализовано 15 вариантов
   указанного преобразования, мнемонические описания которых содержатся в перечислении \ref kdf_t.

    \param state Контекст, сожержащий текущее состояние алгоритма выработки производной ключевой информации
    \param key исходный ключ `Kin`, представляющий собой последовательность октетов
     произвольной, отличной от нуля длины
    \param key_size длина исходного ключа в октетах
    \param kdf функция, используемая для генерации производной ключевой информации
    \param label Используемая в алгоритме метка производного ключа. Может принимать значение NULL.
    \param label_size Длина метки (в октетах). Может принимать значение 0.
    \param seed Используемое в алгоритме инициализирующее значение. Должно быть отлично от NULL.
    \param seed_size Длина инициализирующего значения (в октетах). Должно быть отлично от нуля.
    \param iv Начальное значение `K0` для вырабатываемой последовательности ключей `K1`, `K2`, ...
       Если `iv` принимает значение NULL, то в качестве `K0` используется нулевой вектор.
    \param iv_size Длина начального значения (в октетах).
       Если `iv_size` меньше, чем выход функции `Mac`, то начальное значение `K0` дополняется нулями в старших разрядах.
       Если `iv_size` больше, чем выход функции `Mac`, то старшие разряды отбрасываются.
       Если `iv_size = 0`, то в качестве `K0` используется нулевой вектор.
    \param count Максимальное количество ключей, которое может быть выработано.
    \return В случае возникновения ошибки функция возвращает ее код. В случае успеха
     возвращается \ref ak_error_ok (ноль).                                                         */
/* ----------------------------------------------------------------------------------------------- */
 int ak_kdf_state_create( ak_kdf_state state, ak_uint8 *key, const size_t key_size, kdf_t kdf,
                ak_uint8* label, const size_t label_size, ak_uint8* seed, const size_t seed_size,
                                                  ak_uint8* iv, const size_t iv_size, size_t count )
{
  size_t temp = 0;
  ak_int64 resource = 0;
  int error = ak_error_ok;

 /* выполняем проверки входных параметров */
  if( state == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                           "using null pointer to state context" );
  if(( key == NULL ) || ( key_size == 0 ))
    return ak_error_message( ak_error_null_pointer, __func__, "using incorrect input secret key");
  if(( seed == NULL ) || ( seed_size == 0 ))
    return ak_error_message( ak_error_null_pointer, __func__, "using incorrect input seed buffer");

 /* вырабатываем промежуточный ключ */
  memset( state, 0, sizeof( struct kdf_state ));
  state->algorithm = kdf;

 /* вырабатываем промежуточный ключ */
  switch(( kdf >> 4 )&0xF ) {
    case 1: /* nmac */
      if(( error = ak_hmac_create_nmac( &state->key.hkey )) != ak_error_ok )
       return ak_error_message( error, __func__, "incorrect creation of nmac context" );
      if(( error = ak_hmac_set_key( &state->key.hkey, seed, seed_size )) == ak_error_ok ) {
        error = ak_hmac_ptr( &state->key.hkey, key, key_size, state->ivbuffer, 32 );
      }
      ak_hmac_destroy( &state->key.hkey );
      if( error != ak_error_ok )
        return ak_error_message( error, __func__,
                                     "incorrect creation of intermediate key using nmac context" );
      break;

    case 2: /* hmac */
      if(( error = ak_hmac_create_streebog512( &state->key.hkey )) != ak_error_ok )
       return ak_error_message( error, __func__, "incorrect creation of hmac context" );
      if(( error = ak_hmac_set_key( &state->key.hkey, seed, seed_size )) == ak_error_ok ) {
       /* здесь важно, что ak_hash_context_streebog_finalize помещает в массив interkey
          младшие байты выработанного вектора. При наличии контрольного примера, необходимо проверить это. */
        error = ak_hmac_ptr( &state->key.hkey, key, key_size, state->ivbuffer, 32 );
      }
      ak_hmac_destroy( &state->key.hkey );
      if( error != ak_error_ok )
        return ak_error_message( error, __func__,
                                     "incorrect creation of intermediate key using hmac context" );
      break;

    case 3: /* xor */
      if(( key_size != 32 ) || ( seed_size != 32 )) return ak_error_message(
                        ak_error_wrong_key_length, __func__, "using unsupported key/seed length" );
      for( int i = 0; i < 32; i++ ) state->ivbuffer[i] = key[i]^seed[i];
      break;

    default:
      return ak_error_message( ak_error_undefined_function, __func__,
                          "using unsupported descriptor of intermediate key derivation function" );
      break;
  }

 /* формируем ключ и проверяем ограничения на его использование */
  switch( kdf&0xF ) {
    case 1: /* magma */
      state->block_size = 8;
      state->state_size = ak_min( state->block_size + label_size + 16, sizeof( state->ivbuffer ));
      /* значение имитовставки + счетчик ключей (8 октетов) + метка +
                                                  + максимальное количество ключей (8 октетов) */
      state->number = 0;
      state->max = ( ak_uint64 )count;
      resource = ak_libakrypt_get_option_by_name( "magma_cipher_resource" );
      if( state->max*( 1+ state->state_size / state->block_size ) > resource ) {
        ak_error_message_fmt( error = ak_error_low_key_resource, __func__,
                  "the expected number of derivative keys is very large (must be less than %ld)",
                                            resource/( 1+ state->state_size / state->block_size ));
        goto labex;
      }
      if(( error = ak_bckey_create_magma( &state->key.bkey )) != ak_error_ok ) {
        ak_error_message( error, __func__, "incorrect creation of magma context" );
        goto labex;
      }
      if(( error = ak_bckey_set_key( &state->key.bkey, state->ivbuffer, 32 )) != ak_error_ok ) {
        ak_error_message( error, __func__, "incorrect assigning a secret key to magma context" );
        ak_bckey_destroy( &state->key.bkey  );
        goto labex;
      }
      break;

    case 2: /* kuznechik */
      state->block_size = 16;
      state->state_size = ak_min( state->block_size + label_size + 16, sizeof( state->ivbuffer ));
      /* значение имитовставки + счетчик ключей (8 октетов) + метка +
                                                  + максимальное количество ключей (8 октетов) */
      state->number = 0;
      state->max = ( ak_uint64 )count;
      resource = ak_libakrypt_get_option_by_name( "kuznechik_cipher_resource" );
      if( state->max*( 1+ state->state_size / state->block_size ) > resource ) {
        ak_error_message_fmt( error = ak_error_low_key_resource, __func__,
                  "the expected number of derivative keys is very large (must be less than %ld)",
                                            resource/( 1+ state->state_size / state->block_size ));
        goto labex;
      }
      if(( error = ak_bckey_create_kuznechik( &state->key.bkey )) != ak_error_ok ) {
        ak_error_message( error, __func__, "incorrect creation of kuznechik context" );
        goto labex;
      }
      if(( error = ak_bckey_set_key( &state->key.bkey, state->ivbuffer, 32 )) != ak_error_ok ) {
        ak_error_message( error, __func__,
                                         "incorrect assigning a secret key to kuznechik context" );
        ak_bckey_destroy( &state->key.bkey  );
        goto labex;
      }
      break;

    case 3: /* hmac256 */
      state->block_size = 32;
      state->state_size = ak_min( state->block_size + label_size + 16, sizeof( state->ivbuffer ));
      /* значение имитовставки + счетчик ключей (8 октетов) + метка +
                                                  + максимальное количество ключей (8 октетов) */
      state->number = 0;
      state->max = ( ak_uint64 )count;
      resource = ak_libakrypt_get_option_by_name( "hmac_key_count_resource" );
      if( 2*state->max > resource ) {
        ak_error_message_fmt( error = ak_error_low_key_resource, __func__,
                   "the expected number of derivative keys is very large (must be less than %ld)",
                                                                                      resource/2 );
        goto labex;
      }
      if(( error = ak_hmac_create_streebog256( &state->key.hkey )) != ak_error_ok ) {
        ak_error_message( error, __func__, "incorrect creation of hmac-streebog256 context" );
        goto labex;
      }
      if(( error = ak_hmac_set_key( &state->key.hkey, state->ivbuffer, 32 )) != ak_error_ok ) {
        ak_error_message( error, __func__,
                                  "incorrect assigning a secret key to hmac-streebog256 context" );
        ak_hmac_destroy( &state->key.hkey  );
        goto labex;
      }
      break;

    case 4: /* hmac512 */
      state->block_size = 64;
      state->state_size = ak_min( state->block_size + label_size + 16, sizeof( state->ivbuffer ));
      /* значение имитовставки + счетчик ключей (8 октетов) + метка +
                                                  + максимальное количество ключей (8 октетов) */
      state->number = 0;
      state->max = ( ak_uint64 )count;
      resource = ak_libakrypt_get_option_by_name( "hmac_key_count_resource" );
      if( 2*state->max > resource ) {
        ak_error_message_fmt( error = ak_error_low_key_resource, __func__,
                   "the expected number of derivative keys is very large (must be less than %ld)",
                                                                                      resource/2 );
        goto labex;
      }
      if(( error = ak_hmac_create_streebog512( &state->key.hkey )) != ak_error_ok ) {
        ak_error_message( error, __func__, "incorrect creation of hmac-streebog512 context" );
        goto labex;
      }
      if(( error = ak_hmac_set_key( &state->key.hkey, state->ivbuffer, 32 )) != ak_error_ok ) {
        ak_error_message( error, __func__,
                                  "incorrect assigning a secret key to hmac-streebog512 context" );
        ak_hmac_destroy( &state->key.hkey  );
        goto labex;
      }
      break;

    case 5: /* nmac */
      state->block_size = 32;
      state->state_size = ak_min( state->block_size + label_size + 16, sizeof( state->ivbuffer ));
      /* значение имитовставки + счетчик ключей (8 октетов) + метка +
                                                  + максимальное количество ключей (8 октетов) */
      state->number = 0;
      state->max = ( ak_uint64 )count;
      resource = ak_libakrypt_get_option_by_name( "hmac_key_count_resource" );
      if( 2*state->max > resource ) {
        ak_error_message_fmt( error = ak_error_low_key_resource, __func__,
                   "the expected number of derivative keys is very large (must be less than %ld)",
                                                                                      resource/2 );
        goto labex;
      }
      if(( error = ak_hmac_create_nmac( &state->key.hkey )) != ak_error_ok ) {
        ak_error_message( error, __func__, "incorrect creation of nmac-streebog context" );
        goto labex;
      }
      if(( error = ak_hmac_set_key( &state->key.hkey, state->ivbuffer, 32 )) != ak_error_ok ) {
        ak_error_message( error, __func__,
                                  "incorrect assigning a secret key to nmac-streebog context" );
        ak_hmac_destroy( &state->key.hkey  );
        goto labex;
      }
      break;

    default:
      ak_error_message( ak_error_undefined_function, __func__,
                         "using unsupported descriptor of intermediate key derivation algorithm" );
      goto labex;
      break;
  }

 /* в заключение, формируем строку */
  memset( state->ivbuffer, 0, sizeof( state->ivbuffer ));
  if( iv != NULL ) memcpy( state->ivbuffer, iv, ak_min( iv_size, state->block_size ));
  ak_uint64_to_ptr( state->number, ( state->ivbuffer +state->block_size +8 ));

  memcpy( state->ivbuffer +state->block_size +8, label,
                  temp = ak_min( label_size, sizeof( state->ivbuffer ) - state->block_size - 16 ));
 /* последним параметром записываем максимальную длину ключевой информации в битах */
  ak_uint64_to_ptr( state->max*state->block_size, ( state->ivbuffer +state->block_size +8 +temp ));

  labex:
    if( error != ak_error_ok ) memset( state->ivbuffer, 0, sizeof( state->ivbuffer ));

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param state Контекст, содержащий текущее состояние алгоритма выработки производной
    ключевой информации                                                                            */
/* ----------------------------------------------------------------------------------------------- */
 size_t ak_kdf_state_get_block_size( ak_kdf_state state )
{
  if( state == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                           "using null pointer to state context" );
 return state->block_size;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param state Контекст, содержащий текущее состояние алгоритма выработки производной
    ключевой информации
    \param buffer Область памяти, куда помещается выработанная ключевая информайия
    \param buffer_size Размер вырабатываемой ключевой информации (в октетах)
    \return В случае успеха функция возвращает ноль (ak_error_ok),
    в противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_kdf_state_next( ak_kdf_state state, ak_pointer buffer, const size_t buffer_size )
{
  ak_uint64 index = 0;
  size_t i, count, tail;
  ak_uint8 *ptr = buffer;
  ak_function_finalize *mac = NULL;

  if( state == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                           "using null pointer to state context" );
  if( buffer == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                              "using null pointer to key buffer" );
  if( buffer_size == 0 ) return ak_error_message( ak_error_zero_length, __func__,
                                                        "using null key buffer with zero length" );
 /* вычисляем количество шагов */
  count = buffer_size / state->block_size;
  tail = buffer_size - count*state->block_size;

  if(( state->number + count + (tail > 0 )) >= state->max )
    return ak_error_message( ak_error_low_key_resource, __func__,
                                                      "resource of key information is exhausted" );
  ak_ptr_to_uint64(( state->ivbuffer +state->block_size ), index );
  if( index != state->number ) return ak_error_message( ak_error_invalid_value,
                                                      __func__, "incorrect internal state value" );
 /* определяем функцию для сжатия */
  switch( state->algorithm&0xF ) {
    case 1:
    case 2: mac = (ak_function_finalize *) ak_bckey_cmac;
      break;
    default: mac = (ak_function_finalize *) ak_hmac_ptr;
      break;
  }

 /* основной цикл */
  for( i = 0; i < count; i++ ) {
    state->number++;
    ak_uint64_to_ptr( state->number, ( state->ivbuffer +state->block_size ));
    mac( &state->key.bkey, state->ivbuffer, state->state_size, state->ivbuffer, state->block_size );
    memcpy( ptr, state->ivbuffer, state->block_size );
    ptr += state->block_size;
  }

  if( tail ) {
    state->number++;
    ak_uint64_to_ptr( state->number, ( state->ivbuffer +state->block_size ));
    mac( &state->key.bkey, state->ivbuffer, state->state_size, state->ivbuffer, state->block_size );
    memcpy( ptr, state->ivbuffer, tail );
  }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param state Контекст, содержащий текущее состояние алгоритма выработки производной 
    ключевой информации
    \return В случае успеха функция возвращает ноль (ak_error_ok),
    в противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_kdf_state_destroy( ak_kdf_state state )
{
  if( state == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                           "using null pointer to state context" );
  ak_ptr_wipe( state->ivbuffer, sizeof( state->ivbuffer ), &state->key.bkey.key.generator );

  switch( state->algorithm&0xF ) {
  case 1:
  case 2:
    ak_bckey_destroy( &state->key.bkey );
    break;
  case 3:
  case 4:
  case 5:
    ak_hmac_destroy( &state->key.hkey );
    break;
  default:
    return ak_error_message( ak_error_undefined_value, __func__,
                                                        "using state with unsupported algorithm" );
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \example test-kdf-state.c                                                                      */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                        ak_kdf.c */
/* ----------------------------------------------------------------------------------------------- */
