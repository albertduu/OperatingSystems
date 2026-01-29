CC = gcc
CFLAGS = -g -c
AR = ar -rc
RANLIB = ranlib

LIB_NAME = libthread-worker.a
OBJS = thread-worker.o queue.o

all: clean thread-worker.a

thread-worker.a: thread-worker.o queue.o
	$(AR) libthread-worker.a thread-worker.o queue.o
	$(RANLIB) libthread-worker.a

thread-worker.o: thread-worker.c thread-worker.h

ifeq ($(SCHED), PSJF)
	$(CC) $(CFLAGS) -DPSJF thread-worker.c -o thread-worker.o
else ifeq ($(SCHED), MLFQ)
	$(CC) $(CFLAGS) -DMLFQ thread-worker.c -o thread-worker.o
else ifeq ($(SCHED), CFS)
	$(CC) $(CFLAGS) -DCFS thread-worker.c -o thread-worker.o
else
	@echo "Error: Unknown scheduling algorithm. Use one of:"
	@echo "    make SCHED=PSJF"
	@echo "    make SCHED=MLFQ"
	@echo "    make SCHED=CFS"
	@exit 1
endif

queue.o: queue.c thread-worker.h
	$(CC) $(CFLAGS) queue.c -o queue.o

clean:
	rm -rf testfile *.o *.a
