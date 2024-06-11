# -------------------------------------------------------------------------------------------------- #
# Copyright (c) 2014 - 2023 by Axel Kenzo, axelkenzo@mail.ru
#
# MakeDoc.cmake
# -------------------------------------------------------------------------------------------------- #
find_program( GZIP gzip )
if( GZIP )
  message( "-- gzip found (${GZIP})" )
else()
  message( "-- gzip not found" )
endif()

find_program( SPHINX sphinx-build )
if( SPHINX )
  message( "-- sphinx-build found (${SPHINX})" )
else()
  message( "-- sphinx-build not found" )
endif()

find_program( DOXYGEN doxygen )
if( DOXYGEN )
  message( "-- doxygen found (${DOXYGEN})" )
else()
  message( "-- doxygen not found" )
endif()

find_program( LATEXMK latexmk )
if( LATEXMK )
  message( "-- latexmk found (${LATEXMK})" )
else()
  message( "-- latexmk not found" )
endif()

find_program( QHELPGENERATOR qhelpgenerator )
if( QHELPGENERATOR )
  message( "-- qhelpgenerator found (${QHELPGENERATOR})" )
else()
  message( "-- qhelpgenerator not found" )
endif()

# -------------------------------------------------------------------------------------------------- #
if( UNIX )

  # ------------------------------------------------------------------------------
  # короткий путь генерации только для выработки sphinx-документов
  # (в форматах html и pdf)
  # ------------------------------------------------------------------------------
  if( SPHINX )
    configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/doc/Makefile.in ${CMAKE_CURRENT_BINARY_DIR}/sphinx/Makefile @ONLY )
    configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/doc/conf.py.in ${CMAKE_CURRENT_SOURCE_DIR}/doc/conf.py @ONLY )

   # html
    set( script ${CMAKE_CURRENT_BINARY_DIR}/make-sphinx-${FULL_VERSION}.sh )
    file( WRITE ${script} "#/bin/bash\n" )
    file( APPEND ${script} "# формируем документацию для сайта в формате html\n\n" )
   # формируем каталог с собранной воедино документацией
    file( APPEND ${script} "mkdir -p ${CMAKE_CURRENT_BINARY_DIR}/sphinx \n" )
    file( APPEND ${script} "cd ${CMAKE_CURRENT_BINARY_DIR}/sphinx \n" )
   # строим красивый вывод в html
   # (собираем архив без включения каталога html)
    file( APPEND ${script} "make html\n" )
   # формируем консольный мануал (в сжатом виде)
   # и сохраняем изначальный (несжатый) man в дереве исходных кодов
    file( APPEND ${script} "make man\n" )
    file( APPEND ${script} "cp ${CMAKE_CURRENT_BINARY_DIR}/sphinx/man/aktool.1 ${CMAKE_CURRENT_SOURCE_DIR}/aktool \n" )
    file( APPEND ${script} "cp ${CMAKE_CURRENT_BINARY_DIR}/sphinx/man/aktool.1 ${CMAKE_CURRENT_BINARY_DIR}/doc/aktool.1 \n" )
    if( GZIP )
      file( APPEND ${script} "gzip --force ${CMAKE_CURRENT_BINARY_DIR}/doc/aktool.1 \n" )
    endif()
    file( APPEND ${script} "cd ${CMAKE_CURRENT_BINARY_DIR}\n" )
   # добавляем цель сборки
    execute_process( COMMAND chmod +x ${script} )
    add_custom_target( sphinx ${script} )
    message("-- Script for sphinx documentation is done (now \"make sphinx\" enabled)")

   # формируем документацию в формате pdf
    if( LATEXMK )

      set( script ${CMAKE_CURRENT_BINARY_DIR}/make-sphinx-pdf-${FULL_VERSION}.sh )
      file( WRITE ${script} "#/bin/bash\n" )
      file( APPEND ${script} "# формируем документацию для сайта в формате pdf\n\n" )
     # формируем каталог с собранной воедино документацией
      file( APPEND ${script} "mkdir -p ${CMAKE_CURRENT_BINARY_DIR}/sphinx \n" )
      file( APPEND ${script} "mkdir -p ${CMAKE_CURRENT_BINARY_DIR}/sphinx/html/_pdf \n" )
      file( APPEND ${script} "cd ${CMAKE_CURRENT_BINARY_DIR}/sphinx \n" )
     # собираем pdf
      file( APPEND ${script} "make latexpdf\n" )
      file( APPEND ${script} "cp ${CMAKE_CURRENT_BINARY_DIR}/sphinx/latex/libakrypt.pdf ${CMAKE_CURRENT_BINARY_DIR}/sphinx/html/_pdf/akrypt-library-doc.pdf\n" )
      file( APPEND ${script} "cp ${CMAKE_CURRENT_BINARY_DIR}/sphinx/latex/libakrypt.pdf ${CMAKE_CURRENT_BINARY_DIR}/doc/libakrypt-doc-${FULL_VERSION}.pdf\n" )
      file( APPEND ${script} "cd ${CMAKE_CURRENT_BINARY_DIR}\n" )
     # добавляем цель сборки
      execute_process( COMMAND chmod +x ${script} )
      add_custom_target( sphinx-pdf ${script} )
      message("-- Script for sphinx-pdf documentation is done (now \"make sphinx-pdf\" enabled)")
    endif()
  endif()

  # ------------------------------------------------------------------------------
  # короткий путь генерации документации с использованием doxygen
  # ------------------------------------------------------------------------------
  if( DOXYGEN )

    configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/doc/Doxyfile.akrypt.in ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile.akrypt @ONLY )

    set( script ${CMAKE_CURRENT_BINARY_DIR}/make-doxygen-${FULL_VERSION}.sh )
    file( WRITE ${script} "#/bin/bash\n" )
    file( APPEND ${script} "# формируем документацию api библиотеки в форматах html и pdf\n\n" )
    file( APPEND ${script} "doxygen Doxyfile.akrypt\n" )

    execute_process( COMMAND chmod +x ${script} )
    add_custom_target( doxygen ${script} )
    message("-- Script for doxygen documentation is done (now \"make doxygen\" enabled)")

  endif()

  # ------------------------------------------------------------------------------
  # формирование команды верхнего уровня
  # ------------------------------------------------------------------------------
  set( script ${CMAKE_CURRENT_BINARY_DIR}/make-doc-${FULL_VERSION}.sh )
  file( WRITE ${script} "#/bin/bash\n" )

  # формируем каталог с собранной воедино документацией
  file( APPEND ${script} "mkdir -p ${CMAKE_CURRENT_BINARY_DIR}/doc\n" )

  if( SPHINX )
    file( APPEND ${script} "make sphinx\n" )
    file( APPEND ${script} "make sphinx-pdf\n" )
  endif()

  if( DOXYGEN )
    configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/doc/libakrypt-header.tex.in ${CMAKE_CURRENT_BINARY_DIR}/libakrypt-header.tex @ONLY )

   # формируем исходные тексты api библиотеки
    file( APPEND ${script} "make doxygen \n" )

   # компилируем tex-файл в обход стандартного Makefile
    file( APPEND ${script} "cd doxygen/latex \n" )
    file( APPEND ${script} "pdflatex -interaction=nonstopmode refman.tex\n")
    file( APPEND ${script} "makeindex refman.idx\n")
    file( APPEND ${script} "pdflatex -interaction=nonstopmode refman.tex\n")
    file( APPEND ${script} "pdflatex -interaction=nonstopmode refman.tex\n")
    file( APPEND ${script} "cd ../.. \n" )

   # копируем pdf
    file( APPEND ${script} "cp ${CMAKE_CURRENT_BINARY_DIR}/doxygen/latex/refman.pdf ${CMAKE_CURRENT_BINARY_DIR}/sphinx/html/_pdf/akrypt-library-api.pdf\n" )
    file( APPEND ${script} "cp ${CMAKE_CURRENT_BINARY_DIR}/doxygen/latex/refman.pdf ${CMAKE_CURRENT_BINARY_DIR}/doc/libakrypt-api-${FULL_VERSION}.pdf\n" )
   # копируем pdf
    if( QHELPGENERATOR )
      file( APPEND ${script} "mv ${CMAKE_CURRENT_BINARY_DIR}/doxygen/html/akrypt-library.qch ${CMAKE_CURRENT_BINARY_DIR}/doc/libakrypt-api-${FULL_VERSION}.qch\n" )
    endif()

   # создаем полноценный архив для отправки на сайт
    file( APPEND ${script} "cd sphinx/html \n" )
    file( APPEND ${script} "mkdir -p _api\n" )
    file( APPEND ${script} "cp ${CMAKE_CURRENT_BINARY_DIR}/doxygen/html/* _api/ \n" )
    file( APPEND ${script} "tar -cjvf ${CMAKE_CURRENT_BINARY_DIR}/doc/libakrypt-doc-${FULL_VERSION}.tar.bz2 *\n" )
    file( APPEND ${script} "cd ../.. \n" )
  endif()

  # добавляем цель сборки
  execute_process( COMMAND chmod +x ${script} )
  add_custom_target( doc ${script} )
  message("-- High level script for documentation is done (now \"make doc\" enabled)")

endif()
# -------------------------------------------------------------------------------------------------- #
#                                                                                     MakeDoc.cmake  #
# -------------------------------------------------------------------------------------------------- #


