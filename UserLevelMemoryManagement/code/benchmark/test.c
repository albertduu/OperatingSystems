#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include "../my_vm.h"

#define SIZE 5
#define ARRAY_SIZE 400

static inline uint32_t add_offset32(void *base_va, size_t off_bytes) {
    uint32_t base = VA2U(base_va);        // 32-bit simulated VA
    uint32_t off  = (uint32_t)off_bytes;  // offsets fit 32-bit here
    return base + off;
}

int main(void) {

    printf("Allocating three arrays of %d bytes\n", ARRAY_SIZE);

    void *a = n_malloc(ARRAY_SIZE);
    uint32_t old_a = VA2U(a);
    void *b = n_malloc(ARRAY_SIZE);
    void *c = n_malloc(ARRAY_SIZE);

    int x = 1;
    int y, z;
    int i = 0, j = 0;
    uint32_t address_a = 0, address_b = 0, address_c = 0;

    printf("Addresses of the allocations (32-bit VAs): %" PRIx32 ", %" PRIx32 ", %" PRIx32 "\n",
           VA2U(a), VA2U(b), VA2U(c));

    printf("Storing integers to generate a SIZExSIZE matrix\n");
    for (i = 0; i < SIZE; i++) {
        for (j = 0; j < SIZE; j++) {
            address_a = add_offset32(a, (size_t)i * SIZE * sizeof(int) + (size_t)j * sizeof(int));
            address_b = add_offset32(b, (size_t)i * SIZE * sizeof(int) + (size_t)j * sizeof(int));
            put_data(U2VA(address_a), &x, sizeof(int));
            put_data(U2VA(address_b), &x, sizeof(int));
        }
    }

    printf("Fetching matrix elements stored in the arrays\n");
    for (i = 0; i < SIZE; i++) {
        for (j = 0; j < SIZE; j++) {
            address_a = add_offset32(a, (size_t)i * SIZE * sizeof(int) + (size_t)j * sizeof(int));
            address_b = add_offset32(b, (size_t)i * SIZE * sizeof(int) + (size_t)j * sizeof(int));
            get_data(U2VA(address_a), &y, sizeof(int));
            get_data(U2VA(address_b), &z, sizeof(int));
            printf("%d ", y);
        }
        printf("\n");
    }

    printf("Performing matrix multiplication with itself!\n");
    mat_mult(a, b, SIZE, c);

    for (i = 0; i < SIZE; i++) {
        for (j = 0; j < SIZE; j++) {
            address_c = add_offset32(c, (size_t)i * SIZE * sizeof(int) + (size_t)j * sizeof(int));
            get_data(U2VA(address_c), &y, sizeof(int));
            printf("%d ", y);
        }
        printf("\n");
    }

    printf("Freeing the allocations!\n");
    n_free(a, ARRAY_SIZE);
    n_free(b, ARRAY_SIZE);
    n_free(c, ARRAY_SIZE);

    printf("Checking if allocations were freed!\n");
    a = n_malloc(ARRAY_SIZE);
    if (VA2U(a) == old_a)
        printf("free function works\n");
    else
        printf("free function does not work\n");

    // avoid leak in this probe-based check
    n_free(a, ARRAY_SIZE);

    return 0;
}

