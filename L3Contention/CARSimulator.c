#include <stdio.h>
#include <sched.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>

#define NR_SET      (2048)
#define NR_ASSOC    (88)
#define BLKSIZE     (64)
#define CACHESIZE   (NR_SET*NR_ASSOC*BLKSIZE)
#define PGSIZE      (2*CACHESIZE)
#define NR_BLK      (PGSIZE/BLKSIZE)

void *huge, *var;

void* alloc() {
    huge = mmap(NULL, PGSIZE, PROT_WRITE|PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS|MAP_HUGETLB, -1, 0);
    return huge == MAP_FAILED ? NULL : huge;
}

int setfifo() {
    struct sched_param param;
    param.sched_priority = sched_get_priority_max(SCHED_FIFO);
    return sched_setscheduler(0, SCHED_FIFO, &param);
}

void accessL3() {
    register uint64_t p1, p2, p3, p4, p1base, p2base, p3base, p4base, step, p1end, p2end, p3end, p4end;
    p1 = p1base = (uint64_t)huge;
    p2 = p2base = (uint64_t)p1base + BLKSIZE;
    p3 = p3base = (uint64_t)p2base + BLKSIZE;
    p4 = p4base = (uint64_t)p3base + BLKSIZE;
    step = BLKSIZE << 2;
    p4end = p1base + PGSIZE;
    p3end = p4end - BLKSIZE;
    p2end = p3end - BLKSIZE;
    p1end = p2end - BLKSIZE;
    while (1) {
        var = *(void**)p1;
        var = *(void**)p2;
        var = *(void**)p3;
        var = *(void**)p4;
        asm volatile (NOPSTR);
        p1 = p1 + step >= p1end ? p1base : p1 + step;
        p2 = p2 + step >= p2end ? p2base : p2 + step;
        p3 = p3 + step >= p3end ? p3base : p3 + step;
        p4 = p4 + step >= p4end ? p4base : p4 + step;
    }
}

int main(int argc, char *argv[]) {
    if (NULL == alloc() || 0 != setfifo()) {
        puts("Faild to alloc.");
        return -1;
    }
    
    accessL3();

    munmap(huge, PGSIZE);
    return 0;
}
