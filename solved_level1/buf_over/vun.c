#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input)
{
    char buffer[10];
    strcpy(buffer, input); // Vulnerable to buffer overflow

    if (strcmp(buffer, "angr") == 0)
    {
        printf("You found the secret path!\n");
    }
    else
    {
        printf("Try again!\n");
    }
}

int main(int argc, char *argv[])
{
    if (argc > 1)
    {
        vulnerable_function(argv[1]);
    }
    else
    {
        printf("Usage: %s <input>\n", argv[0]);
    }
    return 0;
}
