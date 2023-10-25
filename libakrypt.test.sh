#!/bin/bash
compilerList="gcc-9 gcc-10 gcc-11 gcc-12 gcc-13 gcc-14 gcc-15 musl-gcc clang-11 clang-12 clang-13 clang-14 clang-15 clang-16 clang-17 clang-18 tcc"

# формируем каталог для проведения экспериментов
mkdir -p global.build
cd global.build

for name in $compilerList
do
	$name --version 2>> /dev/null
	if [ $? = 0 ];
        then
		echo "--------------------------------------------------------------------------------"
		mkdir -p $name.build
		cd $name.build
# выполняем настройку
		cmake -DCMAKE_C_COMPILER=$name -DAK_STATIC_LIB=ON -DAK_EXAMPLES=ON -DAK_TESTS=ON ../..
# выполняем сборку
		make
# выполняем тестирование
		make test
# выполняем проверку корректности криптографических тестов
		./aktool test --crypto
# выполняем запуск тестов в окружении vslgrind
		valgrind --version >> /dev/null 2>>/dev/null
		if [ $? = 0 ];
		then
			valgrind ./aktool test --crypto
		fi
# не выполняем очистку созданных каталогов
		cd ..
		echo "--------------------------------------------------------------------------------"	
	fi
done

cd ..

