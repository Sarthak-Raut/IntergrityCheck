//
// Created by sarth on 14-11-2022.
//

#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <android/log.h>

#define LOG(...) ((void)__android_log_print(ANDROID_LOG_INFO, "native-lib", __VA_ARGS__))
#define ARRLEN(arr) (sizeof(arr) / sizeof(arr[0]))
#define CSTR(str) str
#define PROCFS CSTR("/proc")
#define RDONLY 00000000

typedef struct {
    void *base;
    void *end;
    unsigned long    size;
}module;

static void CloseFileBuf(char **pfilebuf)
{
    if (pfilebuf && *pfilebuf) {
        free(*pfilebuf);
        *pfilebuf = (char *)nullptr;
    }
}

int EnumModules(pid_t pid){

    char maps_path[ARRLEN(PROCFS) + 64] = { 0 };
    char *maps_buf;
    char *ptr;

    snprintf(maps_path, ARRLEN(maps_path),CSTR("%s/%d/maps"), PROCFS, pid);

    int fd;
    unsigned long total = 0;
    char  c;
    ssize_t rdsize;
    char *filebuf = (char *)nullptr;

    fd = open(maps_path, RDONLY);

    if (fd == -1)
        return 0;

    while ((rdsize = read(fd, &c, sizeof(c)) > 0)) {
        char *old_filebuf;

        old_filebuf = filebuf;
        filebuf = (char *)calloc(total + 2, sizeof(c));
        if (old_filebuf) {
            if (filebuf)
                strncpy(filebuf, old_filebuf, total);
            free(old_filebuf);
        }

        if (!filebuf) {
            total = 0;
            break;
        }

        filebuf[total++] = c;
        filebuf[total] = CSTR('\x00');
    }

    if (filebuf) {
        filebuf[total] = CSTR('\x00');
        maps_buf = filebuf;
    }

    close(fd);

    for (ptr = maps_buf; ptr && (ptr = strchr(ptr, CSTR('/'))); ptr = strchr(ptr, CSTR('\n'))) {

        char *tmp;
        char *holder;
        char *path;
        unsigned long pathlen;
        module mod;

        tmp = strchr(ptr, CSTR('\n'));
        pathlen = (unsigned long)(
                ((unsigned long)tmp - (unsigned long)ptr) /
                sizeof(tmp[0])
        );

        path = (char *)calloc(pathlen + 1, sizeof(char));
        if (!path) {
            break;
        }

        strncpy(path, ptr, pathlen);
        path[pathlen] = CSTR('\x00');

        holder = maps_buf;
        for (tmp = maps_buf;(unsigned long)(tmp = strchr(tmp, CSTR('\n'))) < (unsigned long)ptr; tmp = &tmp[1])
            holder = &tmp[1];

        mod.base = (void*)strtoul(holder, nullptr, 16);

        holder = ptr;
        for (tmp = ptr;(tmp = strchr(tmp, CSTR('\n'))) && (tmp = strchr(tmp, CSTR('/'))); tmp = &tmp[1]) {
            if (strncmp(tmp, path, pathlen))
                break;
            holder = tmp;
        }

        ptr = holder;

        holder = maps_buf;
        for (tmp = maps_buf; (unsigned long)( tmp = strchr(tmp, CSTR('\n'))) < (unsigned long)ptr; tmp = &tmp[1])
            holder = &tmp[1];

        holder = strchr(holder, CSTR('-'));
        holder = &holder[1];
        mod.end = (void*)strtoul(holder, nullptr, 16);
        mod.size = (
                (unsigned long)mod.end - (unsigned long)mod.base
        );

        CloseFileBuf(&maps_buf);

        LOG(" mod.base = %p ", mod.base);
        LOG(" mod.end = %p ", mod.end);
        LOG(" mod.size = %d ", mod.size);
    }

    return 0;
}
