/*
 * vulnshop file processor
 *
 * Reads an uploaded file path from argv[1], verifies the caller is
 * allowed to read it, then loads its contents into memory and prints
 * a hex dump.  Used by the admin "inspect upload" tool.
 */
#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

static char *read_file_contents(int fd, size_t size, size_t *out_len) {
    char *buf = malloc(size ? size : 1);
    if (!buf) return NULL;
    size_t got = 0;
    while (got < size) {
        ssize_t n = read(fd, buf + got, size - got);
        if (n < 0) { free(buf); return NULL; }
        if (n == 0) break;
        got += (size_t)n;
    }
    *out_len = got;
    return buf;
}

static void build_label(char *dest, size_t size, const char *user_supplied_label) {
    snprintf(dest, size, "label:%.*s", (int)(size - sizeof("label:")), user_supplied_label);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <file> <label>\n", argv[0]);
        return 2;
    }
    const char *path  = argv[1];
    const char *label = argv[2];

    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "access denied\n");
        return 1;
    }

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_size < 0 || st.st_size > 16 * 1024 * 1024) {
        fprintf(stderr, "invalid file\n");
        close(fd);
        return 1;
    }
    fprintf(stderr, "[info] file size at check: %lld\n", (long long)st.st_size);

    size_t len = 0;
    char *data = read_file_contents(fd, (size_t)st.st_size, &len);
    close(fd);
    if (!data) {
        perror("read_file_contents");
        return 1;
    }

    char *label_buf = malloc(32);
    if (!label_buf) { free(data); return 1; }
    build_label(label_buf, 32, label);
    printf("%s\n", label_buf);

    for (size_t i = 0; i < len; i++) printf("%02x", (unsigned char)data[i]);
    printf("\n");

    free(data);
    free(label_buf);
    return 0;
}
