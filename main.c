#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

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

int
main (int argc, char **argv)
{
    protected();
    uint64_t length = protected_end - protected;
    uint8_t *bytes = (uint8_t*) protected;
    printf("num bytes: %ld\n", length - 1);
    for (int i = 0; i < length; i++)
        printf("0x%x ", bytes[i]);
    putchar('\n');
    return 0;
}
