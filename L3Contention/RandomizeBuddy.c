#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#define PGSIZE  (4096)
#define REPEAT  (512)

int main(int argc, char *argv[]) {
    char *pg[REPEAT], *cur, *end;
    unsigned size[REPEAT], i, nrpg, release;

    srand(time(NULL));
    for (i=0; i<REPEAT; ++i) {
        nrpg = rand() % 1024;
        size[i] = nrpg * PGSIZE;
        pg[i] = (char*)mmap(NULL, size[i], PROT_WRITE|PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (MAP_FAILED != pg[i]) {
            for (cur=pg[i], end=pg[i]+size[i]; cur<end; cur+=PGSIZE) {
                cur[0] = 'a';
            }
            release = rand() % 2;
            if (release) {
                munmap(pg[i], size[i]);
                pg[i] = MAP_FAILED;
            }
        }
    }

    for (i=0; i<REPEAT; ++i) {
        if (MAP_FAILED != pg[i]) {
            munmap(pg[i], size[i]);
        }
    }

    return 0;
}