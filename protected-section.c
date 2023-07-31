#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>

void
error (const char* format, ...)
{
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    putchar('\n');
    exit(1);
}

void
protected ()
{
    /* 
     * Using a string literal here like s = "foobar" would cause the compiler
     * to put the string "foobar" into a different section of memory (the data
     * section). But we want to encrypt everything inside this area. So instead
     * we construct the string as an array of bytes so the compiler cannot
     * place these bytes it into a section that won't be encrypted.
     */
    static const char s[] = {'s', '3', 'c', 'r', '3', 't', '\0'};
    puts(s);
}

void
protected_end ()
{
    /* 
     * Meant to be empty -- simply marks the end of the protected section so
     * that we can properly get the correct length of the protected section.
     */
}


/*
 * Performs bit-arithmetic with the size of the page to clear the least
 * significant `size` bits of the pointer to find the nearest start of the
 * page.
 */
void*
getpage (void *p, uint64_t size)
{
    return (void*)((uint64_t)p & ~(size - 1));
}

/*
 * Mark the protected function as writeable.
 */
void
mark_protected_writable ()
{
    /*
     * The mprotect system call *must* be called on an address that is page
     * aligned and *must* be the length of the entire page.  This allows us to
     * write to this program's instructions which are normally read/execute
     * only.
     */
    uint64_t pagesize = sysconf(_SC_PAGE_SIZE);
    void* page = getpage(protected, pagesize);
    if (mprotect(page, pagesize, PROT_WRITE | PROT_EXEC | PROT_READ) < 0)
        error("mprotect: %s", strerror(errno));
}

void
copyme ()
{
    puts("you are walking inside the garden!");
    exit(1);
}

void
copyme_end ()
{
}

#include <libkern/OSCacheControl.h>
#include <pthread.h>

int
main (int argc, char **argv)
{
    void* addr = mmap(NULL, 4096,
            PROT_WRITE | PROT_READ,
            MAP_PRIVATE | MAP_ANON,
            //PROT_WRITE | PROT_EXEC | PROT_READ,
            //MAP_PRIVATE | MAP_ANON | MAP_JIT,
            -1, 0);
    if (addr == MAP_FAILED)
        error("mmap: %s", strerror(errno));

    memcpy(addr, copyme, copyme_end - copyme);

    if (mprotect(addr, 4096, PROT_EXEC | PROT_READ) < 0)
        error("mprotect: %s", strerror(errno));

    ((void (*) (void)) addr)();

    //pthread_jit_write_protect_np(0);
    //sys_icache_invalidate(addr, 4096);
    //memcpy(addr, copyme, copyme_end - copyme);
    //
    //pthread_jit_write_protect_np(1);
    //sys_icache_invalidate(addr, 4096);
    //((void (*) (void)) addr)();

    return 0;
}
