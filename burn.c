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
 * Get how many bytes into the executable file the protected function should be.
 */
uint64_t
get_protected_offset ()
{
    void* page = getpage(protected, getpagesize());
    return (void*)protected - page;
}

int
main (int argc, char **argv)
{
    protected();

    const char *file = argv[0];
    const char zero = 0;
    FILE *f = fopen(file, "w+");
    if (!f)
        error("%s: %s", file, strerror(errno));
    fseek(f, get_protected_offset(), SEEK_CUR);
    for (int i = 0; i < protected_end - protected; i++)
        fwrite(&zero, 1, 1, f);
    fclose(f);

    return 0;
}
