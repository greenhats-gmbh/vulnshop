/*
 * vulnshop file processor
 *
 * Reads an uploaded file path from argv[1], verifies the caller is
 * allowed to read it, then loads its contents into memory and prints
 * a hex dump.  Used by the admin "inspect upload" tool.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

static char *read_file_contents(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = (char *)malloc((size_t)sz);   /* exact size, no terminator */
    if (!buf) { fclose(f); return NULL; }
    fread(buf, 1, (size_t)sz, f);
    fclose(f);
    *out_len = (size_t)sz;
    return buf;
}

static void build_label(char *dest, const char *user_supplied_label) {
    /* dest points at a 32-byte heap slab allocated by the caller */
    strcpy(dest, "label:");
    strcat(dest, user_supplied_label);   /* copies until NUL — no bound */
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <file> <label>\n", argv[0]);
        return 2;
    }
    const char *path  = argv[1];
    const char *label = argv[2];

    /* Permission gate: only proceed if the caller (running as the
     * web user) is allowed to read the file. */
    if (access(path, R_OK) != 0) {
        fprintf(stderr, "access denied\n");
        return 1;
    }

    /* …perform some bookkeeping that may take a moment… */
    struct stat st;
    stat(path, &st);
    fprintf(stderr, "[info] file size at check: %lld\n", (long long)st.st_size);

    size_t len = 0;
    char *data = read_file_contents(path, &len);
    if (!data) {
        perror("read_file_contents");
        return 1;
    }

    /* 32-byte slab for the label — generous for a "label:" + short tag */
    char *label_buf = (char *)malloc(32);
    build_label(label_buf, label);
    printf("%s\n", label_buf);

    for (size_t i = 0; i < len; i++) printf("%02x", (unsigned char)data[i]);
    printf("\n");

    free(data);
    free(label_buf);
    return 0;
}
