
#include "my_vm.h"
#include <string.h>   // optional for memcpy if you later implement put/get
#include <math.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>

// -----------------------------------------------------------------------------
// Global Declarations (optional)
// -----------------------------------------------------------------------------

typedef unsigned long ulong;
typedef unsigned int  uint;


struct tlb tlb_store; // Placeholder for your TLB structure

// Optional counters for TLB statistics
static unsigned long long tlb_lookups = 0;
static unsigned long long tlb_misses  = 0;

// -----------------------------------------------------------------------------
// Setup
// -----------------------------------------------------------------------------
static unsigned char *phys_mem     = NULL;
static size_t         mem_size     = MEMSIZE;
static pde_t         *pgdir_root   = NULL;
static unsigned char *virt_bitmap  = NULL;
static unsigned char *phys_bitmap  = NULL;

static uint32_t total_pages = 0;

static uint32_t num_bits_offset = 0;
static uint32_t num_bits_pde    = 0;
static uint32_t num_bits_pte    = 0;
static uint32_t num_bits_vpn    = 0;

static ulong VBITMAP_SIZE = 0;
static ulong PBITMAP_SIZE = 0;

static pthread_mutex_t vm_lock = PTHREAD_MUTEX_INITIALIZER;

static void free_program(void);
static void setup_bitcounts(void);

static void set_bit(unsigned char *bitmap, ulong index);
static void clear_bit(unsigned char *bitmap, ulong index);
static int  get_bit(const unsigned char *bitmap, ulong index);

static inline void *pa_to_host(paddr32_t pa);
static inline paddr32_t host_to_pa(void *ptr);

static void get_indices_from_va(vaddr32_t va, unsigned long *pde_index, unsigned long *pte_index, unsigned long *offset);
static vaddr32_t get_next_free_va(ulong size_in_pages);

static void *get_next_avail_phys(int num_pages);
static int   clear_page_phys_bitmap(void *page_phys_addr);
static int   set_page_phys_bitmap(void *page_phys_addr);

static int    setup_page_directory(void);
static pte_t *create_page_table_and_link_to_dir(pde_t *pgdir_entry_location);
static void  *create_page_and_link_to_page_table(pte_t *page_table_entry_location);

static void set_bit(unsigned char *bitmap, ulong index) {
    bitmap[index / 8] |= (1u << (index % 8));
}

static void clear_bit(unsigned char *bitmap, ulong index) {
    bitmap[index / 8] &= ~(1u << (index % 8));
}

static int get_bit(const unsigned char *bitmap, ulong index) {
    return (bitmap[index / 8] >> (index % 8)) & 1u;
}

static inline void *pa_to_host(paddr32_t pa) {
    return (void *)(phys_mem + pa);
}

static inline paddr32_t host_to_pa(void *ptr) {
    return (paddr32_t)((unsigned char *)ptr - phys_mem);
}

static void setup_bitcounts(void) {
    uint32_t shift = 0;
    uint32_t page  = PGSIZE;
    while ((1u << shift) < page) {
        shift++;
    }
    num_bits_offset = shift;                 

    num_bits_pte = (VA_BITS - num_bits_offset) / 2;          
    num_bits_pde = VA_BITS - num_bits_offset - num_bits_pte; 
    num_bits_vpn = num_bits_pde + num_bits_pte;              

    total_pages  = (uint32_t)(mem_size / PGSIZE);
    PBITMAP_SIZE = total_pages;                  
    VBITMAP_SIZE = (ulong)(MAX_MEMSIZE / PGSIZE);
}

static void free_program(void) {
    free(phys_mem);
    free(virt_bitmap);
    free(phys_bitmap);
}

static int clear_page_phys_bitmap(void *page_phys_addr) {
    paddr32_t pa = host_to_pa(page_phys_addr);
    unsigned long page_index = pa / PGSIZE;
    clear_bit(phys_bitmap, page_index);
    return 0;
}

static int set_page_phys_bitmap(void *page_phys_addr) {
    paddr32_t pa = host_to_pa(page_phys_addr);
    unsigned long page_index = pa / PGSIZE;
    set_bit(phys_bitmap, page_index);
    return 0;
}

static void get_indices_from_va(vaddr32_t va,
                                unsigned long *pde_index,
                                unsigned long *pte_index,
                                unsigned long *offset) {
    unsigned long vpn = ((unsigned long)va) >> num_bits_offset;
    *pde_index = vpn >> num_bits_pte;
    *pte_index = vpn & ((1UL << num_bits_pte) - 1);
    *offset    = ((unsigned long)va) & ((1UL << num_bits_offset) - 1);
}

static vaddr32_t get_next_free_va(ulong size_in_pages) {
    uint  byte_index  = 0;
    uint  bit_index   = 0;
    ulong current_seq = 0;

    ulong bitmap_bytes = (VBITMAP_SIZE + 7) / 8;

    for (uint i = 0; i < bitmap_bytes; ++i) {
        unsigned char byte = virt_bitmap[i];

        if (byte == 0xFF) {
            current_seq = 0;
            continue;
        }

        for (int bit = 0; bit < 8; ++bit) {
            ulong bit_idx = (ulong)i * 8 + (ulong)bit;
            if (bit_idx >= VBITMAP_SIZE) break;

            if ((byte >> bit) & 1u) {
                current_seq = 0;
            } else {
                if (current_seq == 0) {
                    byte_index = i;
                    bit_index  = (uint)bit;
                }
                current_seq++;
                if (current_seq == size_in_pages) {
                    ulong start_bit = (ulong)byte_index * 8 + (ulong)bit_index;
                    return (vaddr32_t)(start_bit * PGSIZE);
                }
            }
        }
    }
    return (vaddr32_t)1; // sentinel (valid VAs are multiples of PGSIZE)
}

static void *get_next_avail_phys(int num_pages) {
    uint  byte_index  = 0;
    uint  bit_index   = 0;
    ulong current_seq = 0;

    ulong bitmap_bytes = (PBITMAP_SIZE + 7) / 8;

    for (uint i = 0; i < bitmap_bytes; ++i) {
        unsigned char byte = phys_bitmap[i];

        if (byte == 0xFF) {
            current_seq = 0;
            continue;
        }

        for (int bit = 0; bit < 8; ++bit) {
            ulong bit_idx = (ulong)i * 8 + (ulong)bit;
            if (bit_idx >= PBITMAP_SIZE) break;

            if ((byte >> bit) & 1u) {
                current_seq = 0;
            } else {
                if (current_seq == 0) {
                    byte_index = i;
                    bit_index  = (uint)bit;
                }
                current_seq++;
                if (current_seq == (ulong)num_pages) {
                    ulong start_bit = (ulong)byte_index * 8 + (ulong)bit_index;
                    return (void *)(phys_mem + start_bit * PGSIZE);
                }
            }
        }
    }

    return NULL;
}

static int setup_page_directory(void) {
    if (pgdir_root != NULL) return 0;

    unsigned long num_pde_entries = 1UL << num_bits_pde;
    unsigned long pde_size_bytes  = num_pde_entries * sizeof(pde_t);
    unsigned long pde_size_pages  = pde_size_bytes / PGSIZE;
    if (pde_size_bytes % PGSIZE != 0) pde_size_pages++;

    /* Put page directory at PA=0 */
    pgdir_root = (pde_t *)pa_to_host(0);
    memset(pgdir_root, 0, pde_size_pages * PGSIZE);

    for (unsigned long i = 0; i < pde_size_pages; i++) {
        set_bit(phys_bitmap, i);
    }

    return 0;
}

static pte_t *create_page_table_and_link_to_dir(pde_t *pgdir_entry_location) {
    assert(pgdir_root != NULL && "Page directory not initialized");

    unsigned long num_pte_entries = 1UL << num_bits_pte;
    unsigned long pte_size_bytes  = num_pte_entries * sizeof(pte_t);
    unsigned long pte_size_pages  = pte_size_bytes / PGSIZE;
    if (pte_size_bytes % PGSIZE != 0) pte_size_pages++;

    void *first_page = get_next_avail_phys((int)pte_size_pages);
    if (!first_page) {
        fprintf(stderr, "Error: No available pages for page table.\n");
        return NULL;
    }

    for (unsigned long i = 0; i < pte_size_pages; i++) {
        set_page_phys_bitmap((unsigned char *)first_page + i * PGSIZE);
    }

    pde_t *free_pde = pgdir_entry_location;
    assert(*free_pde == 0 && "Page table already linked");

    paddr32_t pt_pa = host_to_pa(first_page);
    *free_pde       = pt_pa;

    memset(first_page, 0, pte_size_pages * PGSIZE);

    return (pte_t *)first_page;
}

static void *create_page_and_link_to_page_table(pte_t *page_table_entry_location) {
    void *page_phys_addr = get_next_avail_phys(1);
    if (!page_phys_addr) {
        fprintf(stderr, "Error: No available pages for page.\n");
        return NULL;
    }

    set_page_phys_bitmap(page_phys_addr);

    pte_t *free_pte = page_table_entry_location;
    assert(*free_pte == 0 && "Page already linked");

    paddr32_t frame_pa = host_to_pa(page_phys_addr);
    *free_pte          = frame_pa;

    memset(page_phys_addr, 0, PGSIZE);
    return page_phys_addr;
}

/*
 * set_physical_mem()
 * ------------------
 * Allocates and initializes simulated physical memory and any required
 * data structures (e.g., bitmaps for tracking page use).
 *
 * Return value: None.
 * Errors should be handled internally (e.g., failed allocation).
 */
void set_physical_mem(void) {
    pthread_mutex_lock(&vm_lock);
    if (phys_mem != NULL) {
        pthread_mutex_unlock(&vm_lock);
        return;
    }

    setup_bitcounts();

    phys_mem = (unsigned char *)calloc(1, mem_size);
    if (!phys_mem) {
        fprintf(stderr, "Error: Unable to allocate physical memory.\n");
        pthread_mutex_unlock(&vm_lock);
        exit(EXIT_FAILURE);
    }

    ulong phys_bytes = (PBITMAP_SIZE + 7) / 8;
    ulong virt_bytes = (VBITMAP_SIZE + 7) / 8;

    phys_bitmap = (unsigned char *)calloc(1, phys_bytes);
    virt_bitmap = (unsigned char *)calloc(1, virt_bytes);

    if (!phys_bitmap || !virt_bitmap) {
        fprintf(stderr, "Error: Unable to allocate bitmaps.\n");
        pthread_mutex_unlock(&vm_lock);
        free(phys_mem);
        exit(EXIT_FAILURE);
    }
    set_bit(phys_bitmap, 0);
    set_bit(virt_bitmap, 0);

    for (int i = 0; i < TLB_ENTRIES; i++) {
        tlb_store.entries[i].vpn   = 0;
        tlb_store.entries[i].pfn   = 0;
        tlb_store.entries[i].valid = false;
        tlb_store.entries[i].last_used = 0;
    }
    tlb_store.lookups = 0;
    tlb_store.misses  = 0;

    atexit(free_program);
    pthread_mutex_unlock(&vm_lock);
}

// -----------------------------------------------------------------------------
// TLB
// -----------------------------------------------------------------------------

/*
 * TLB_add()
 * ---------
 * Adds a new virtual-to-physical translation to the TLB.
 * Ensure thread safety when updating shared TLB data.
 *
 * Return:
 *   0  -> Success (translation successfully added)
 *  -1  -> Failure (e.g., TLB full or invalid input)
 */
int TLB_add(void *va, void *pa)
{
    if (!va || !pa) return -1;

    vaddr32_t v    = VA2U(va);
    unsigned int vpn   = v >> num_bits_offset;
    unsigned int index = vpn % TLB_ENTRIES;

    tlb_store.entries[index].vpn   = vpn;
    tlb_store.entries[index].pfn   = host_to_pa(pa);  // frame base PA
    tlb_store.entries[index].valid = true;
    tlb_store.entries[index].last_used =
        (unsigned long long)time(NULL);

    return 0;
}

/*
 * TLB_check()
 * -----------
 * Looks up a virtual address in the TLB.
 *
 * Return:
 *   Pointer to the corresponding page table entry (PTE) if found.
 *   NULL if the translation is not found (TLB miss).
 */
pte_t *TLB_check(void *va)
{
    if (!va) return NULL;

    vaddr32_t v    = VA2U(va);
    unsigned int vpn   = v >> num_bits_offset;
    unsigned int index = vpn % TLB_ENTRIES;

    tlb_lookups++;
    tlb_store.lookups++;

    if (tlb_store.entries[index].valid &&
        tlb_store.entries[index].vpn == vpn) {
        // pfn field holds the frame PA (what a PTE would hold)
        return &tlb_store.entries[index].pfn;
    }

    tlb_misses++;
    tlb_store.misses++;
    return NULL;
}

/*
 * print_TLB_missrate()
 * --------------------
 * Calculates and prints the TLB miss rate.
 *
 * Return value: None.
 */
void print_TLB_missrate(void)
{
    pthread_mutex_lock(&vm_lock);
    double miss_rate = 0.0;
    if (tlb_lookups > 0) {
        miss_rate = (double)tlb_misses / (double)tlb_lookups;
    }
    fprintf(stderr, "TLB miss rate %lf \n", miss_rate);
    pthread_mutex_unlock(&vm_lock);
}

// -----------------------------------------------------------------------------
// Page Table
// -----------------------------------------------------------------------------

/*
 * translate()
 * -----------
 * Translates a virtual address to a physical address.
 * Perform a TLB lookup first; if not found, walk the page directory
 * and page tables using a two-level lookup.
 *
 * Return:
 *   Pointer to the PTE structure if translation succeeds.
 *   NULL if translation fails (e.g., page not mapped).
 */
pte_t *translate(pde_t *pgdir, void *va)
{
    if (!pgdir || !va) return NULL;

    pthread_mutex_lock(&vm_lock);

    // Try TLB first under the lock
    pte_t *pte_from_tlb = TLB_check(va);
    if (pte_from_tlb != NULL) {
        pthread_mutex_unlock(&vm_lock);
        return pte_from_tlb;
    }

    vaddr32_t v = VA2U(va);
    unsigned long pde_index, pte_index, offset;
    get_indices_from_va(v, &pde_index, &pte_index, &offset);

    pde_t *pde_entry = pgdir + pde_index;
    if (*pde_entry == 0) {
        pthread_mutex_unlock(&vm_lock);
        return NULL;
    }

    paddr32_t pt_pa = *pde_entry;
    pte_t *pt       = (pte_t *)pa_to_host(pt_pa);

    pte_t *pte_entry = pt + pte_index;
    if (*pte_entry == 0) {
        pthread_mutex_unlock(&vm_lock);
        return NULL;
    }

    // Cache in TLB: VA page -> frame base
    paddr32_t frame_pa = *pte_entry;
    void *frame_ptr    = pa_to_host(frame_pa);
    TLB_add(va, frame_ptr);

    pthread_mutex_unlock(&vm_lock);
    return pte_entry;
}

/*
 * map_page()
 * -----------
 * Establishes a mapping between a virtual and a physical page.
 * Creates intermediate page tables if necessary.
 *
 * Return:
 *   0  -> Success (mapping created)
 *  -1  -> Failure (e.g., no space or invalid address)
 */
int map_page(pde_t *pgdir, void *va, void *pa)
{
    if (!pgdir || !va) return -1;

    vaddr32_t v = VA2U(va);
    unsigned long pde_index, pte_index, offset;
    get_indices_from_va(v, &pde_index, &pte_index, &offset);

    if (offset != 0) {
        fprintf(stderr, "map_page(): va must be page-aligned\n");
        return -1;
    }

    if (pgdir_root == NULL) {
        setup_page_directory();
    }

    pde_t *pde_entry = pgdir + pde_index;

    if (*pde_entry == 0) {
        pte_t *new_pt = create_page_table_and_link_to_dir(pde_entry);
        if (!new_pt) {
            fprintf(stderr, "map_page(): Error creating page table.\n");
            return -1;
        }
    }

    paddr32_t pt_pa = *pde_entry;
    pte_t *pt       = (pte_t *)pa_to_host(pt_pa);
    pte_t *pte_entry = pt + pte_index;

    void *frame_ptr = pa;
    if (!frame_ptr) {
        frame_ptr = create_page_and_link_to_page_table(pte_entry);
        if (!frame_ptr) {
            fprintf(stderr, "map_page(): Error creating page.\n");
            return -1;
        }
    } else {
        assert(*pte_entry == 0 && "Page already mapped");
        paddr32_t frame_pa = host_to_pa(frame_ptr);
        *pte_entry = frame_pa;
        set_page_phys_bitmap(frame_ptr);
    }

    return 0;
}

// -----------------------------------------------------------------------------
// Allocation
// -----------------------------------------------------------------------------

/*
 * get_next_avail()
 * ----------------
 * Finds and returns the base virtual address of the next available
 * block of contiguous free pages.
 *
 * Return:
 *   Pointer to the base virtual address if available.
 *   NULL if there are no sufficient free pages.
 */
void *get_next_avail(int num_pages)
{
    vaddr32_t va = get_next_free_va((ulong)num_pages);
    if (va == (vaddr32_t)1) return NULL;
    return U2VA(va);
}

/*
 * n_malloc()
 * -----------
 * Allocates a given number of bytes in virtual memory.
 * Initializes physical memory and page directories if not already done.
 *
 * Return:
 *   Pointer to the starting virtual address of allocated memory (success).
 *   NULL if allocation fails.
 */
void *n_malloc(unsigned int num_bytes)
{
    if (num_bytes == 0) return NULL;

    pthread_mutex_lock(&vm_lock);

    if (!phys_mem) {
        pthread_mutex_unlock(&vm_lock);
        set_physical_mem();
        pthread_mutex_lock(&vm_lock);
    }
    if (!pgdir_root) {
        setup_page_directory();
    }

    ulong num_pages = num_bytes / PGSIZE;
    if (num_bytes % PGSIZE != 0) num_pages++;

    vaddr32_t va = get_next_free_va(num_pages);
    if (va == (vaddr32_t)1) {
        fprintf(stderr, "Error: No available virtual pages for allocation.\n");
        pthread_mutex_unlock(&vm_lock);
        return NULL;
    }

    for (ulong i = 0; i < num_pages; i++) {
        vaddr32_t page_va = va + (vaddr32_t)(i * PGSIZE);
        if (map_page(pgdir_root, U2VA(page_va), NULL) == -1) {
            fprintf(stderr, "Error: map_page failed in n_malloc.\n");
            pthread_mutex_unlock(&vm_lock);
            return NULL;
        }
    }

    for (ulong i = 0; i < num_pages; i++) {
        vaddr32_t page_va = va + (vaddr32_t)(i * PGSIZE);
        ulong vpn = ((ulong)page_va) >> num_bits_offset;
        set_bit(virt_bitmap, vpn);
    }

    void *ret = U2VA(va);
    pthread_mutex_unlock(&vm_lock);
    return ret;
}

/*
 * n_free()
 * ---------
 * Frees one or more pages of memory starting at the given virtual address.
 * Marks the corresponding virtual and physical pages as free.
 * Removes the translation from the TLB.
 *
 * Return value: None.
 */
void n_free(void *va, int size)
{
    if (!va || size <= 0 || !pgdir_root) return;

    pthread_mutex_lock(&vm_lock);

    ulong size_in_pages = ((ulong)size + PGSIZE - 1) / PGSIZE;
    vaddr32_t base_va = VA2U(va);

    assert(size_in_pages <= 1024 && "n_free: size too large for static arrays");
    vaddr32_t vpages[1024];
    unsigned long pde_indices[1024];
    int pde_indices_count = 0;

    for (ulong i = 0; i < size_in_pages; i++) {
        vpages[i] = base_va + (vaddr32_t)(i * PGSIZE);
        ulong vpn = ((ulong)vpages[i]) >> num_bits_offset;
        if (get_bit(virt_bitmap, vpn) == 0) {
            fprintf(stderr, "Error: Virtual address not valid in n_free.\n");
            pthread_mutex_unlock(&vm_lock);
            return;
        }
    }

    for (ulong i = 0; i < size_in_pages; i++) {
        vaddr32_t vpage = vpages[i];

        unsigned long pde_index, pte_index, offset;
        get_indices_from_va(vpage, &pde_index, &pte_index, &offset);

        pde_t *pde_entry = pgdir_root + pde_index;
        if (*pde_entry == 0) {
            fprintf(stderr, "Error: PDE missing in n_free.\n");
            pthread_mutex_unlock(&vm_lock);
            return;
        }

        paddr32_t pt_pa = *pde_entry;
        pte_t *pte_table = (pte_t *)pa_to_host(pt_pa);
        pte_t *pte_entry = pte_table + pte_index;

        if (*pte_entry == 0) {
            fprintf(stderr, "Error: PTE missing in n_free.\n");
            pthread_mutex_unlock(&vm_lock);
            return;
        }

        paddr32_t frame_pa = *pte_entry;
        void *frame_ptr     = pa_to_host(frame_pa);

        clear_page_phys_bitmap(frame_ptr);
        *pte_entry = 0;

        ulong vpn = ((ulong)vpage) >> num_bits_offset;
        clear_bit(virt_bitmap, vpn);

        int found = 0;
        for (int j = 0; j < pde_indices_count; j++) {
            if (pde_indices[j] == pde_index) {
                found = 1;
                break;
            }
        }
        if (!found) pde_indices[pde_indices_count++] = pde_index;
    }

    /* Optionally, we could also invalidate matching TLB entries here. */

    /* Free empty page tables */
    for (int i = 0; i < pde_indices_count; i++) {
        unsigned long pde_index = pde_indices[i];
        pde_t *pde_entry = pgdir_root + pde_index;

        if (*pde_entry == 0) continue;

        paddr32_t pt_pa = *pde_entry;
        pte_t *pte_table = (pte_t *)pa_to_host(pt_pa);

        int empty = 1;
        unsigned long num_pte_entries = 1UL << num_bits_pte;
        for (unsigned long j = 0; j < num_pte_entries; j++) {
            if (pte_table[j] != 0) {
                empty = 0;
                break;
            }
        }

        if (empty) {
            unsigned long pte_size_bytes = num_pte_entries * sizeof(pte_t);
            unsigned long pte_size_pages = pte_size_bytes / PGSIZE;
            if (pte_size_bytes % PGSIZE != 0) pte_size_pages++;

            for (unsigned long k = 0; k < pte_size_pages; k++) {
                void *addr = (unsigned char *)pa_to_host(pt_pa) + k * PGSIZE;
                clear_page_phys_bitmap(addr);
            }

            *pde_entry = 0;
        }
    }

    pthread_mutex_unlock(&vm_lock);
}

// -----------------------------------------------------------------------------
// Data Movement
// -----------------------------------------------------------------------------

/*
 * put_data()
 * ----------
 * Copies data from a user buffer into simulated physical memory using
 * the virtual address. Handle page boundaries properly.
 *
 * Return:
 *   0  -> Success (data written successfully)
 *  -1  -> Failure (e.g., translation failure)
 */
int put_data(void *va, void *val, int size)
{
    if (!va || !val || size <= 0 || !pgdir_root) return -1;

    int bytes_written = 0;
    vaddr32_t base_va = VA2U(va);

    while (bytes_written < size) {
        vaddr32_t current_va = base_va + (vaddr32_t)bytes_written;

        pte_t *pte_entry = translate(pgdir_root, U2VA(current_va));
        if (!pte_entry) {
            fprintf(stderr, "Error: Invalid VA in put_data.\n");
            return -1;
        }

        paddr32_t frame_pa = *pte_entry;
        unsigned long offset_in_page =
            ((unsigned long)current_va) & ((1UL << num_bits_offset) - 1);
        unsigned long bytes_left_in_page = PGSIZE - offset_in_page;
        unsigned long bytes_to_copy      =
            (unsigned long)size - (unsigned long)bytes_written;
        if (bytes_to_copy > bytes_left_in_page) bytes_to_copy = bytes_left_in_page;

        void *pa_ptr = (unsigned char *)pa_to_host(frame_pa) + offset_in_page;
        memcpy(pa_ptr, (unsigned char *)val + bytes_written, bytes_to_copy);

        bytes_written += (int)bytes_to_copy;
    }

    return 0;
}

/*
 * get_data()
 * -----------
 * Copies data from simulated physical memory (accessed via virtual address)
 * into a user buffer.
 *
 * Return value: None.
 */
void get_data(void *va, void *val, int size)
{
    if (!va || !val || size <= 0 || !pgdir_root) return;

    int bytes_read = 0;
    vaddr32_t base_va = VA2U(va);

    while (bytes_read < size) {
        vaddr32_t current_va = base_va + (vaddr32_t)bytes_read;

        pte_t *pte_entry = translate(pgdir_root, U2VA(current_va));
        if (!pte_entry) {
            fprintf(stderr, "Error: Invalid VA in get_data.\n");
            return;
        }

        paddr32_t frame_pa = *pte_entry;
        unsigned long offset_in_page =
            ((unsigned long)current_va) & ((1UL << num_bits_offset) - 1);
        unsigned long bytes_left_in_page = PGSIZE - offset_in_page;
        unsigned long bytes_to_copy      =
            (unsigned long)size - (unsigned long)bytes_read;
        if (bytes_to_copy > bytes_left_in_page) bytes_to_copy = bytes_left_in_page;

        void *pa_ptr = (unsigned char *)pa_to_host(frame_pa) + offset_in_page;
        memcpy((unsigned char *)val + bytes_read, pa_ptr, bytes_to_copy);

        bytes_read += (int)bytes_to_copy;
    }
}

// -----------------------------------------------------------------------------
// Matrix Multiplication
// -----------------------------------------------------------------------------

/*
 * mat_mult()
 * ----------
 * Performs matrix multiplication of two matrices stored in virtual memory.
 * Each element is accessed and stored using get_data() and put_data().
 *
 * Return value: None.
 */
void mat_mult(void *mat1, void *mat2, int size, void *answer)
{
    int i, j, k;
    uint32_t a, b, c;

    for (i = 0; i < size; i++) {
        for (j = 0; j < size; j++) {
            c = 0;
            for (k = 0; k < size; k++) {
                vaddr32_t addr_a = VA2U(mat1) + (vaddr32_t)(i * size * sizeof(int)) + (vaddr32_t)(k * sizeof(int));
                vaddr32_t addr_b = VA2U(mat2) + (vaddr32_t)(k * size * sizeof(int)) + (vaddr32_t)(j * sizeof(int));
                void *addr_a_va = U2VA(addr_a);
                void *addr_b_va = U2VA(addr_b);
                get_data(addr_a_va, &a, sizeof(int));
                get_data(addr_b_va, &b, sizeof(int));
                c += (a * b);
            }
            vaddr32_t addr_c = VA2U(answer) + (vaddr32_t)(i * size * sizeof(int)) + (vaddr32_t)(j * sizeof(int));
            void *addr_c_va = U2VA(addr_c);
            put_data(addr_c_va, &c, sizeof(int));
        }
    }
}

