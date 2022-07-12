#include <string.h>
#include <stdio.h>

void function2(char *str) {
    char buffer[5];
    strcpy(buffer, str);
    printf("buffer %s\n", buffer);
}

void function1(char *str){
    char buffer[5];
    strcpy(buffer, str);
    printf("buffer %s\n", buffer);
}

int main(int argc, char *argv[])
{
    function2(argv[1]);
    function1(argv[1]);
    printf("Executed normally\n");
    return 0;
}
