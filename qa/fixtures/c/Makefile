all: hello.o utils.o
	gcc -o hello hello.o utils.o

hello.o: hello.c
	gcc -c hello.c -I ./

utils.o: subdir/utils.c
	gcc -c subdir/utils.c -I ./

clean:
	rm -rf *.o
	rm -rf hello
