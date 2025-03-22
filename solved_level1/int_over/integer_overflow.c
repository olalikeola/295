#include <stdio.h>
#include <limits.h>

void integer_overflow(unsigned int b)
{
    unsigned int a = UINT_MAX;
    unsigned int result = a + b; // Integer overflow

    // Check for overflow
    if (result < a)
    {
        printf("Result: overflowed\n");
    }
    else
    {
        printf("Result: denied\n");
    }
}

int main()
{
    unsigned int b;

    printf("Enter an unsigned integer value to add to UINT_MAX: ");
    scanf("%u", &b);

    integer_overflow(b);
    return 0;
}
