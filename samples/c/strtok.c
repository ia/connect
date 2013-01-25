#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main(int argc, char *argv[])
{
    char *str, *token;
    char *ptr;
    int j;

    if (argc != 4) {
        fprintf(stderr, "Usage: %s string delim subdelim\n",
                argv[0]);
        exit(EXIT_FAILURE);
    }

    for (j = 1, str = argv[1]; ; j++, str = NULL) {
        token = strtok_r(str, argv[2], &ptr);
        if (token == NULL)
            break;
        printf("%d: %s\n", j, token);
/*
        for (str2 = token; ; str2 = NULL) {
            subtoken = strtok_r(str2, argv[3], &saveptr2);
            if (subtoken == NULL)
                break;
            printf(" --> %s\n", subtoken);
        }
*/
    }

    exit(EXIT_SUCCESS);
}

