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

void protected (const char *filename);
void protected_end ();

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
 * Get how many bytes into the executable file the protected function should be.
 */
uint64_t
get_protected_offset ()
{
    void* page = getpage(protected, getpagesize());
    return (void*)protected - page;
}

void
protected (const char *filename)
{
    /*
     * Using a string literal here like s = "foobar" would cause the compiler
     * to put the string "foobar" into a different section of memory (the data
     * section). But we want to encrypt everything inside this area rather than
     * load a pre-crafted string from the data section. Instead we construct
     * the string using instructions so the data is created and protected in
     * the same place.
     */
    char s[7];
    s[0] = 's';
    s[1] = '3';
    s[2] = 'c';
    s[3] = 'r';
    s[4] = '3';
    s[5] = 't';
    s[6] = '\0';
    puts(s);

    /*
     * Executable files like ./burn aren't executed from the file itself. The
     * executable file itself is just a binary file format for the kernel to
     * read and process. The actual bytes which contain the instructions exists
     * are copied into virtual memory by the kernel from the file. Therefore,
     * we want to change the file itself and not the memory in-process.
     *
     * The operating also attempts to hold the inode of the file while its
     * associated process is executed and usually will either error or create a
     * new file if the "w" flag is passed. Therefore we have to side-step by
     * just reading the contents of our executable, unlinking the file, and
     * then creating a new file with the unlinked filename.
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

    fseek(f, get_protected_offset(), SEEK_CUR);
    char zero = 0;
    for (int i = 0; i < protected_end - protected; i++)
        fwrite(&zero, 1, 1, f);
    fclose(f);
    chmod(filename, 0775);
}

void
protected_end ()
{
    /*
     * Meant to be empty -- simply marks the end of the protected section so
     * that we can properly get the correct length of the protected section.
     */
}

int
main (int argc, char **argv)
{
    protected(argv[0]);
    return 0;
}
