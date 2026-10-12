/* T88 example: plain C (gcc). */
#include <stdio.h>
#include <unistd.h>

int main(void) {
    char host[256] = {0};
    gethostname(host, sizeof host - 1);
    printf("c ok on %s\n", host);
    return 0;
}
