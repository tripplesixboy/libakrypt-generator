# -------------------------------------------------------------------------------------------------- #
# Copyright (c) 2014 - 2024 by Axel Kenzo, axelkenzo@mail.ru
#
# MakeAktool.cmake
# -------------------------------------------------------------------------------------------------- #
set( AKTOOL_SOURCES
     aktool/aktool.c
     aktool/aktool_asn1.c
     aktool/aktool_key.c
     aktool/aktool_show.c
     aktool/aktool_test.c
     aktool/aktool_icode.c
     aktool/aktool_icode_evaluate.c
     aktool/aktool_icode_export_import.c
     aktool/aktool_icode_config.c
   )
set( AKTOOL_FILES
     aktool/aktool.h
     aktool/getopt.h
     aktool/getopt.c
   )

# -------------------------------------------------------------------------------------------------- #
if( AK_HAVE_GETOPT_H )
else()
  set( AKTOOL_SOURCES ${AKTOOL_SOURCES} aktool/getopt.c )
endif()

# -------------------------------------------------------------------------------------------------- #
message( STATUS "Sources for aktool utility:" )
foreach( filename ${AKTOOL_SOURCES} )
  message( NOTICE "      ${filename}" )
endforeach()

# -------------------------------------------------------------------------------------------------- #
# Определяем путь для локали
if( AK_LOCALE_PATH )
else()
  if( CMAKE_HOST_UNIX )
    if( AK_FREEBSD )
      set( AK_LOCALE_PATH "/usr/local/share/locale" )
    else()
      set( AK_LOCALE_PATH "/usr/share/locale" )
    endif()
    add_compile_options( -DLIBAKRYPT_LOCALE_PATH="${AK_LOCALE_PATH}" )
    message( STATUS "Locale path is ${AK_LOCALE_PATH}" )
  endif()
endif()

# -------------------------------------------------------------------------------------------------- #
# дополнительный (опциональный) функционал утилиты aktool
macro( try_aktool_lib _lib _header )
   string( TOUPPER AK_HAVE_${_header}_H AKTOOL_LIB_HEADER )
   if( AK_STATIC_LIB )
     find_library( LIB${_lib}_LIB lib${_lib}.a )
   else()
     find_library( LIB${_lib}_LIB lib${_lib}.so )
   endif()
   if( LIB${_lib}_LIB )
     message( STATUS "lib${_lib} found (${LIB${_lib}_LIB})" )
      find_file( AK_HAVE_${_header}_H ${_header}.h )
      if( AK_HAVE_${_header}_H )
        message(  STATUS "${_header}.h found")
        set( LIBAKRYPT_LIBS ${LIBAKRYPT_LIBS} ${LIB${_lib}_LIB} )
        set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D${AKTOOL_LIB_HEADER}" )
        message( STATUS "Added compile flag -D${AKTOOL_LIB_HEADER}")
      endif()
   endif()
endmacro( try_aktool_lib )

# libbz2
try_aktool_lib( bz2 bzlib )
# libelf
try_aktool_lib( elf gelf )
# libintl
try_aktool_lib( intl libintl )
# libiconv
try_aktool_lib( iconv iconv )

if( LIBAKRYPT_LIBS )
  message( STATUS "Additional libraries for aktool is ${LIBAKRYPT_LIBS}")
endif()

add_executable( aktool ${AKTOOL_SOURCES} )
target_include_directories( aktool PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/aktool" )

if( AK_STATIC_LIB )
  if( AK_BASE )
    target_link_libraries( aktool akrypt-static akbase-static ${LIBAKRYPT_LIBS} )
  else()
    target_link_libraries( aktool akrypt-static ${LIBAKRYPT_LIBS} )
  endif()
else()
  if( AK_BASE )
    target_link_libraries( aktool akrypt-shared akbase-shared ${LIBAKRYPT_LIBS} )
  else()
    target_link_libraries( aktool akrypt-shared ${LIBAKRYPT_LIBS} )
  endif()
endif()

# -------------------------------------------------------------------------------------------------- #
# инсталлируем aktool
install( CODE "execute_process( COMMAND strip -s ${CMAKE_CURRENT_BINARY_DIR}/aktool )" )
install( TARGETS aktool DESTINATION bin )

# компилируем и инсталлируем файлы с рускоязычным переводом утилиты aktool
include( FindGettext )
if( GETTEXT_MSGFMT_EXECUTABLE )
  install( CODE "execute_process( COMMAND ${GETTEXT_MSGFMT_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/aktool/aktool.po -o ${CMAKE_CURRENT_BINARY_DIR}/aktool.mo )" )
  install( FILES ${CMAKE_CURRENT_BINARY_DIR}/aktool.mo DESTINATION ${AK_LOCALE_PATH}/ru/LC_MESSAGES/ )
endif()

# инсталлируем мануал для aktool
set( AK_MAN_PATH ${CMAKE_INSTALL_FULL_MANDIR}/ru/man1 )
string( COMPARE EQUAL ${CMAKE_HOST_SYSTEM_NAME} "FreeBSD" AK_FREEBSD )
if( AK_FREEBSD )
  set( AK_MAN_PATH ${CMAKE_INSTALL_PREFIX}/share/${CMAKE_INSTALL_MANDIR}/man1 )
endif()

if( GZIP )
  install( CODE "execute_process( COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/aktool/aktool.1 ${CMAKE_CURRENT_BINARY_DIR} )" )
  install( CODE "execute_process( COMMAND gzip --force ${CMAKE_CURRENT_BINARY_DIR}/aktool.1 )" )
  install( FILES ${CMAKE_CURRENT_BINARY_DIR}/aktool.1.gz DESTINATION ${AK_MAN_PATH} )
else()
  install( FILES ${CMAKE_CURRENT_SOURCE_DIR}/aktool/aktool.1 DESTINATION ${AK_MAN_PATH} )
endif()

# -------------------------------------------------------------------------------------------------- #
#                                                                                      Aktool.cmake  #
# -------------------------------------------------------------------------------------------------- #
