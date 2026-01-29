
all : test mtest
test: ../my_vm.h
	gcc test.c -L../ -lmy_vm -lpthread -o test

mtest: ../my_vm.h
	gcc multi_test.c -L../ -lmy_vm -lpthread -o mtest 

clean:
	rm -rf test mtest
