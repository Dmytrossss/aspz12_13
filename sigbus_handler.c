#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

long page_size;

struct vma_region {
    void *start;            
    void *end;              
    struct vma_region *next;
};

struct vma_region *head = NULL;


void add_region(void *start, size_t length) {
    struct vma_region *region = malloc(sizeof(struct vma_region));
    if (!region) {
        perror("malloc");
        exit(1);
    }
    region->start = start;
    region->end = (char*)start + length;
    region->next = NULL;


    sigset_t newset, oldset;
    sigemptyset(&newset);
    sigaddset(&newset, SIGBUS);
    if (sigprocmask(SIG_BLOCK, &newset, &oldset)) {
        perror("sigprocmask");
        exit(1);
    }

    region->next = head;
    head = region;

    if (sigprocmask(SIG_SETMASK, &oldset, NULL)) {
        perror("sigprocmask");
        exit(1);
    }
}

void remove_region(void *start, size_t length) {
    void *end = (char*)start + length;

    sigset_t newset, oldset;
    sigemptyset(&newset);
    sigaddset(&newset, SIGBUS);
    if (sigprocmask(SIG_BLOCK, &newset, &oldset)) {
        perror("sigprocmask");
        exit(1);
    }

    struct vma_region *prev = NULL;
    struct vma_region *cur = head;
    while (cur) {
        if (cur->start == start && cur->end == end) {
            if (prev) {
                prev->next = cur->next;
            } else {
                head = cur->next;
            }
            free(cur);
            break;
        }
        prev = cur;
        cur = cur->next;
    }

    if (sigprocmask(SIG_SETMASK, &oldset, NULL)) {
        perror("sigprocmask");
        exit(1);
    }
}

static void sigbus_handler(int sig, siginfo_t *info, void *ucontext) {
    void *fault_addr = info->si_addr;
    int found = 0;
    struct vma_region *cur = head;

    while (cur) {
        if (fault_addr >= cur->start && fault_addr < cur->end) {
            found = 1;
            break;
        }
        cur = cur->next;
    }

    const char *msg;
    if (found) {
        msg = "SIGBUS: mmap-related error\n";
    } else {
        msg = "SIGBUS: physical memory access error\n";
    }
    write(STDERR_FILENO, msg, strlen(msg));
    _exit(1);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <test_case: 1 or 2>\n", argv[0]);
        return 1;
    }
    int test_case = atoi(argv[1]);
    if (test_case != 1 && test_case != 2) {
        fprintf(stderr, "Invalid test_case. Use 1 or 2.\n");
        return 1;
    }

    struct sigaction sa;
    sa.sa_sigaction = sigbus_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    if (sigaction(SIGBUS, &sa, NULL)) {
        perror("sigaction");
        return 1;
    }

    page_size = sysconf(_SC_PAGESIZE);
    if (page_size == -1) {
        perror("sysconf");
        return 1;
    }

    if (test_case == 1) {
        int fd1 = open("file1", O_RDWR | O_CREAT | O_TRUNC, 0666);
        if (fd1 == -1) {
            perror("open file1");
            return 1;
        }
        if (ftruncate(fd1, 2 * page_size) == -1) {
            perror("ftruncate file1");
            close(fd1);
            return 1;
        }
        void *addr1 = mmap(NULL, 2 * page_size, PROT_READ, MAP_PRIVATE, fd1, 0);
        if (addr1 == MAP_FAILED) {
            perror("mmap addr1");
            close(fd1);
            return 1;
        }
        add_region(addr1, 2 * page_size);

        if (ftruncate(fd1, page_size) == -1) {
            perror("ftruncate file1 to page_size");
        }

        char *p1 = (char *)addr1 + page_size;
        printf("Accessing registered mmap area: %p\n", p1);
        fflush(stdout);
        char c1 = *p1; 

        printf("No SIGBUS? Something went wrong.\n");
        munmap(addr1, 2 * page_size);
        close(fd1);
    }
    else if (test_case == 2) {
        int fd2 = open("file2", O_RDWR | O_CREAT | O_TRUNC, 0666);
        if (fd2 == -1) {
            perror("open file2");
            return 1;
        }
        if (ftruncate(fd2, 2 * page_size) == -1) {
            perror("ftruncate file2");
            close(fd2);
            return 1;
        }
        void *addr2 = mmap(NULL, 2 * page_size, PROT_READ, MAP_PRIVATE, fd2, 0);
        if (addr2 == MAP_FAILED) {
            perror("mmap addr2");
            close(fd2);
            return 1;
        }

        if (ftruncate(fd2, page_size) == -1) {
            perror("ftruncate file2 to page_size");
        }

        char *p2 = (char *)addr2 + page_size;
        printf("Accessing unregistered mmap area: %p\n", p2);
        fflush(stdout);
        char c2 = *p2; 

        printf("No SIGBUS? Something went wrong.\n");
        munmap(addr2, 2 * page_size);
        close(fd2);
    }

    return 0;
}
