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
    char s[] = {'s', '3', 'c', 'r', '3', 't', '\0'};
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

/*
 * After `protected` is writable, this XORs each byte of the function with the
 * given key.
 */
void
xor_protected (uint8_t key)
{
    uint64_t len = protected_end - protected;
    uint8_t *bytes = (void*) protected;
    for (int i = 0; i < len; i++)
        bytes[i] ^= key;
}

/*
 * Copy the file to a new file of the same name and return the file descriptor.
 */
FILE*
copy_and_open (const char *filename)
{
    /*
     * We do this because opening a file for writing while it is currently
     * being executed causes the open system call to return the ETXTBSY or
     * "text busy" error. The kernel has the inode of the file mmap'd in memory
     * so it can't be modified that way.  So, we sidestep that limitation by
     * saving all the bytes of the executable file, unlinking the file to that
     * particular inode, and recreating it under a different inode.
     */
    FILE *f = fopen(filename, "r");
    if (!f)
        error("%s: %s", filename, strerror(errno));
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    rewind(f);
    uint8_t bytes[size];
    fread(bytes, size, 1, f);
    fclose(f);

    unlink(filename);
    f = fopen(filename, "w+");
    if (!f)
        error("%s: %s", filename, strerror(errno));
    fwrite(bytes, size, 1, f);
    rewind(f);
    chmod(filename, 0775);

    return f;
}

/*
 * Get how many bytes into the executable file the protected function should be.
 */
uint64_t
get_protected_offset ()
{
    uint64_t pagesize = sysconf(_SC_PAGE_SIZE);
    void* page = getpage(protected, pagesize);
    return (void*)protected - page;
}

/*
 * Check of the protected function has been encrypted yet or not.
 */
bool
is_encrypted ()
{
    /*
     * Every function starts with "push %rbp; mov %rsp, %rbp". Knowing this
     * we can make a very simple check to see if the bytes have either already
     * been encrypted or if they were decrypted successfully.
     */
    uint8_t header[] = { 0x55, 0x48, 0x89, 0xe5 };
    uint8_t *bytes = (uint8_t*) protected;
    for (int i = 0; i < sizeof(header); i++)
        if (bytes[i] != header[i])
            return true;
    return false;
}

void
read_key (const char *str, uint32_t *key)
{
    if (sscanf(str, "0x%x", key) < 1)
        error("Argument `%s' needs to be a hexadecimal!", str);
}

int
main (int argc, char **argv)
{
    uint32_t key = 0;

    if (argc < 2)
        error("Usage: %s [encrypt] <key>", argv[0]);

    if (strcmp(argv[1], "encrypt") == 0) {
        if (is_encrypted())
            error("Already encrypted.");
        /* Encrypt the bytes using the given key */
        read_key(argv[2], &key);
        mark_protected_writable();
        xor_protected(key);
        /* Write those bytes to a new executable file */
        FILE *f = copy_and_open(argv[0]);
        fseek(f, get_protected_offset(), SEEK_CUR);
        fwrite(protected, protected_end - protected, 1, f);
        fclose(f);
        printf("Encrypted.\n");
    }
    else {
        if (!is_encrypted())
            error("Needs to be encrypted first.");
        /* Decrypt the bytes using the given key */
        read_key(argv[1], &key);
        mark_protected_writable();
        xor_protected(key);
        /* If it is still protected exit early, otherwise run it */
        if (is_encrypted())
            error("Bad key.");
        protected();
    }

    return 0;
}
