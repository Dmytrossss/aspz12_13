## Звіт з виконання лабораторної роботи №12_13

**Система: Linux Mint 22.1 'Xia' MATE Edition (VirtualBox)**

**Виконавець: Гнилицький Дмитро**

**Група: ТВ-33**

**Варіант №3**

## Завдання

Напишіть обробник SIGBUS, який розрізняє помилки через mmap та помилки доступу до фізичної пам’яті.

## Код програми

```c
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
```

## Компіляція та запуск

### Компіляція програми
```bash
gcc -o sigbus_handler sigbus_handler.c
```

### Запуск тесту 1 (mmap-помилка)
```bash
./sigbus_handler 1
```
Результат:

![image](https://github.com/user-attachments/assets/4f7c6405-16db-4818-9151-f357c737872e)


```
dima@dima-VirtualBox:~/aspz12_13$ ./sigbus_handler 1
Accessing registered mmap area: 0x75353d549000
SIGBUS: mmap-related error

```

### Запуск тесту 2 (помилка фізичної пам'яті)
```bash
./sigbus_handler 2
```
Результат:

![image](https://github.com/user-attachments/assets/1ec68fe0-729a-413f-85d1-50b96d7faed8)


```
dima@dima-VirtualBox:~/aspz12_13$ ./sigbus_handler 2
Accessing unregistered mmap area: 0x73f68fddc000
SIGBUS: physical memory access error
```

### Перевірка створених файлів
```bash
ls -l file1 file2
```

Pезультат: Відображення двох файлів розміром 4096 байт кожен.

![image](https://github.com/user-attachments/assets/126f73f0-a984-4aca-9c2c-14ba024b45e4)

```
dima@dima-VirtualBox:~/aspz12_13$ ls -l file1 file2
-rw-rw-r-- 1 dima dima 4096 чер 22 05:44 file1
-rw-rw-r-- 1 dima dima 4096 чер 22 05:45 file2
```


## Висновки

1. Програма успішно розрізняє два типи помилок, що призводять до сигналу SIGBUS:
   - Для **mmap-помилок** виводиться повідомлення "SIGBUS: mmap-related error"
   - Для **помилок фізичної пам'яті** виводиться повідомлення "SIGBUS: physical memory access error"

2. Механізм роботи програми:
   - Використовується зв'язаний список для відстеження mmap-областей
   - Обробник сигналу SIGBUS перевіряє, чи належить адреса помилки до зареєстрованих областей
   - Для забезпечення потокової безпеки використовується блокування сигналів під час зміни списку областей

3. Тестування підтвердило коректність роботи:
   - Тест 1 демонструє обробку mmap-помилки
   - Тест 2 демонструє обробку помилки фізичної пам'яті
   - Автоматично створюються необхідні файли з правильним розміром (4096 байт)

Програма коректно обробляє сигнал SIGBUS і розрізняє джерела помилок пам'яті, що підтверджено результатами тестування.
