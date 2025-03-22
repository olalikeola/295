#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vulnerable_function(char *input)
{
    if (strlen(input) > 10)
    {
        printf("Buffer overflow detected!\n");
        exit(1);
    }
    else
    {
        printf("Buffer overflow not detected.\n");
    }
    char buffer[10];
    strcpy(buffer, input); // Vulnerable to buffer overflow

    // printf("Buffer: %s\n", buffer);
}

int main()
{
    char input[50];
    printf("Enter a string: ");
    fgets(input, sizeof(input), stdin);
    vulnerable_function(input);
    return 0;
}
