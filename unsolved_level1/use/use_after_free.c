#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void use_after_free(const char *input)
{
    char *ptr = malloc(10);
    if (ptr == NULL)
    {
        perror("Failed to allocate memory");
        exit(EXIT_FAILURE);
    }

    strncpy(ptr, input, 9); // Copy input to allocated memory
    ptr[9] = '\0';          // Null-terminate the string

    free(ptr);           // Free the allocated memory
    printf("%s\n", ptr); // Use after free
}

int main()
{
    char input[20];

    printf("Enter a string (max 19 characters): ");
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = 0; // Remove newline character

    use_after_free(input);
    return 0;
}
