#include <dirent.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static int run_path(const char *path);

static int run_file(const char *path) {
    FILE *fp = fopen(path, "rb");
    uint8_t *buf = NULL;
    long size;
    int rc = 0;

    if (fp == NULL) {
        return 1;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        rc = 1;
        goto end;
    }
    size = ftell(fp);
    if (size < 0) {
        rc = 1;
        goto end;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        rc = 1;
        goto end;
    }

    buf = (uint8_t *) malloc((size_t) size + 1U);
    if (buf == NULL) {
        rc = 1;
        goto end;
    }

    if ((size > 0) && (fread(buf, 1, (size_t) size, fp) != (size_t) size)) {
        rc = 1;
        goto end;
    }

    LLVMFuzzerTestOneInput(buf, (size_t) size);

end:
    free(buf);
    fclose(fp);
    return rc;
}

static int run_dir(const char *path) {
    DIR *dir = opendir(path);
    struct dirent *entry;
    int rc = 0;

    if (dir == NULL) {
        return 1;
    }

    while ((entry = readdir(dir)) != NULL) {
        char child[4096];

        if ((strcmp(entry->d_name, ".") == 0) || (strcmp(entry->d_name, "..") == 0)) {
            continue;
        }

        if (snprintf(child, sizeof(child), "%s/%s", path, entry->d_name) >= (int) sizeof(child)) {
            rc = 1;
            continue;
        }

        if (run_path(child) != 0) {
            rc = 1;
        }
    }

    closedir(dir);
    return rc;
}

static int run_path(const char *path) {
    struct stat st;

    if (stat(path, &st) != 0) {
        return 1;
    }

    if (S_ISDIR(st.st_mode)) {
        return run_dir(path);
    }
    if (S_ISREG(st.st_mode)) {
        return run_file(path);
    }
    return 0;
}

int main(int argc, char **argv) {
    int rc = 0;

    if (argc <= 1) {
        static const uint8_t empty = 0;
        LLVMFuzzerTestOneInput(&empty, 0U);
        return 0;
    }

    for (int i = 1; i < argc; i++) {
        if (run_path(argv[i]) != 0) {
            rc = 1;
        }
    }

    return rc;
}
