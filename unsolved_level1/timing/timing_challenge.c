#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#define MAX_PASS 20

int check_password(char *pass)
{
    char *secret = "TIMEISKEY";
    int i;
    clock_t start, end;

    start = clock();
    for (i = 0; i < MAX_PASS; i++)
    {
        if (pass[i] != secret[i])
        {
            end = clock();
            if ((end - start) > 1000000)
            {             // 1 second in clock ticks
                return 1; // Timing-based backdoor
            }
            return 0;
        }
    }
    return 1;
}

int main()
{
    char password[MAX_PASS];
    printf("Enter password: ");
    fgets(password, MAX_PASS, stdin);
    password[strcspn(password, "\n")] = 0;

    if (check_password(password))
    {
        printf("Access granted!\n");
    }
    else
    {
        printf("Access denied!\n");
    }

    return 0;
}
