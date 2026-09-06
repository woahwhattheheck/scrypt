/* Synthetic-fixture driver only; the reader and its dependencies are upstream. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "readpass.h"
#include "insecure_memzero.h"
#include "warnp.h"
int main(int argc, char **argv)
{
    char *password = NULL;
    size_t i, length;
    int result;
    if (argc != 2) return 64;
    WARNP_INIT;
    result = readpass_file(&password, argv[1]);
    if (result != 0) {
        if (password != NULL) {
            fprintf(stderr, "Unexpected allocation on failure\n");
            free(password);
            return 65;
        }
        puts("REJECT");
        return 1;
    }
    if (password == NULL) return 66;
    length = strlen(password);
    printf("ACCEPT %zu ", length);
    for (i = 0; i < length; i++) printf("%02x", (unsigned char)password[i]);
    putchar('\n');
    insecure_memzero(password, length);
    free(password);
    return 0;
}
