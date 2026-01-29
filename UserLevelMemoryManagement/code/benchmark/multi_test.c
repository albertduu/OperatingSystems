#include "../my_vm.h"
#include <time.h>
#include <pthread.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define num_threads 15

void *pointers[num_threads];
int ids[num_threads];
pthread_t threads[num_threads];
int alloc_size = 10000;
int matrix_size = 5;

static inline uint32_t add_offset32(void *base_va, size_t off_bytes) {
    uint32_t base = VA2U(base_va);         // 32-bit simulated VA
    uint32_t off  = (uint32_t)off_bytes;   // safe, offsets fit 32-bit here
    return base + off;                      // result VA (32-bit)
}

void *alloc_mem(void *id_arg) {
    int id = *((int *)id_arg);
    pointers[id] = n_malloc(alloc_size);
    return NULL;
}

void *put_mem(void *id_arg) {
    int id = *((int *)id_arg);
    int val = 1;
    void *va_pointer = pointers[id];
    if (!va_pointer) return NULL;

    for (int i = 0; i < matrix_size; i++) {
        for (int j = 0; j < matrix_size; j++) {
            size_t off = (size_t)i * matrix_size * sizeof(int)
                       + (size_t)j * sizeof(int);
            uint32_t addr_u32 = add_offset32(va_pointer, off);
            void *addr_va = U2VA(addr_u32);
            put_data(addr_va, &val, sizeof(int));
            // val++;
        }
    }
    return NULL;
}

void *mat_mem(void *id_arg) {
    int i = *((int *)id_arg);
    if (i + 2 >= num_threads) return NULL;

    void *a = pointers[i];
    void *b = pointers[i + 1];
    void *c = pointers[i + 2];

    if (a && b && c) {
        mat_mult(a, b, matrix_size, c);
    }
    return NULL;
}

void *free_mem(void *id_arg) {
    int id = *((int *)id_arg);
    if (pointers[id]) {
        n_free(pointers[id], alloc_size);
        pointers[id] = NULL;
    }
    return NULL;
}

int main() {
    srand((unsigned)time(NULL));

    for (int i = 0; i < num_threads; i++)
        ids[i] = i;

    // allocate
    for (int i = 0; i < num_threads; i++)
        pthread_create(&threads[i], NULL, alloc_mem, (void *)&ids[i]);
    for (int i = 0; i < num_threads; i++)
        pthread_join(threads[i], NULL);

    printf("Allocated Pointers (as 32-bit VAs):\n");
    for (int i = 0; i < num_threads; i++)
        printf("%" PRIx32 " ", VA2U(pointers[i]));   // print as uint32_t
    printf("\n");

    // initialize memory in threads
    printf("Initializing some of the memory in multiple threads\n");
    for (int i = 0; i < num_threads; i++)
        pthread_create(&threads[i], NULL, put_mem, (void *)&ids[i]);
    for (int i = 0; i < num_threads; i++)
        pthread_join(threads[i], NULL);

    // spot check
    printf("Randomly checking a thread allocation\n");
    int rand_id = rand() % num_threads;
    void *a = pointers[rand_id];
    int val = 0;
    if (a) {
        for (int i = 0; i < matrix_size; i++) {
            for (int j = 0; j < matrix_size; j++) {
                size_t off = (size_t)i * matrix_size * sizeof(int)
                           + (size_t)j * sizeof(int);
                uint32_t addr_u32 = add_offset32(a, off);
                void *addr_va = U2VA(addr_u32);
                get_data(addr_va, &val, sizeof(int));
                printf("%d ", val);
            }
            printf("\n");
        }
    }

    // matrix multiplies: schedule groups of 3
    printf("Performing matrix multiplications in multiple threads\n");
    for (int i = 0; i + 2 < num_threads; i += 3)
        pthread_create(&threads[i], NULL, mat_mem, (void *)&ids[i]);
    for (int i = 0; i + 2 < num_threads; i += 3)
        pthread_join(threads[i], NULL);

    // spot check again
    printf("Randomly checking a thread allocation after matmul\n");
    if (num_threads >= 3) {
        rand_id = (((rand() % (num_threads / 3)) + 1) * 3) - 1;
        a = pointers[rand_id];
        val = 0;
        if (a) {
            for (int i = 0; i < matrix_size; i++) {
                for (int j = 0; j < matrix_size; j++) {
                    size_t off = (size_t)i * matrix_size * sizeof(int)
                               + (size_t)j * sizeof(int);
                    uint32_t addr_u32 = add_offset32(a, off);
                    void *addr_va = U2VA(addr_u32);
                    get_data(addr_va, &val, sizeof(int));
                    printf("%d ", val);
                }
                printf("\n");
            }
        }
    }

    // free in threads
    printf("Freeing everything in multiple threads\n");
    for (int i = 0; i < num_threads; i++)
        pthread_create(&threads[i], NULL, free_mem, (void *)&ids[i]);
    for (int i = 0; i < num_threads; i++)
        pthread_join(threads[i], NULL);

    // policy-agnostic verification using 32-bit VA printing
    void *probe = n_malloc(alloc_size);
    if (probe != NULL) {
        printf("Free Worked! New VA: %" PRIx32 "\n", VA2U(probe));
        n_free(probe, alloc_size);
    } else {
        printf("Some Problem with free!\n");
    }

    return 0;
}

