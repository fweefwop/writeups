#include <stdio.h>
#include <unistd.h>
#include <string.h>
 
void dumpFlag() {
    puts("The blue key to The Gate is '[key removed]'");
}
 
void runIntoTheCty() {
    puts("Running into the C-Ty...");
    char* args[] = {"/bin/sh", NULL};
    execv("/bin/sh", args);
}
 
int main() {
    char input[256];
    gets(input);
    printf(input);
    puts("");
    gets(input);
    printf(input);
    puts("");
}
