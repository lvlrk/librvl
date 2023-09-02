#include <sys/stat.h>
#include "rvl.h"

int main(int argc, char **argv) {
    if(argc < 2) {
        fputs("Usage: rvl <brresfile(s)> ...\n", stderr);
        return 1;
    }

    char *file = NULL;
    brres_t *bp = NULL;
    char tmp[256];
    FILE *fp = NULL;

    for(int i = 1; i < argc; i++) {
        file = argv[1];
        bp = brres_read_file(file);
        brres_print(bp);

        for(uint i = 0; i < bp->n_folders; i++) {
            mkdir(bp->folders[i].name, 0755);

            memset(tmp, 0, 256);
            memcpy(tmp, bp->folders[i].name, strlen(bp->folders[i].name));
            tmp[strlen(bp->folders[i].name)] = '/';

            for(uint j = 0; j < bp->folders[i].n_subfiles; j++) {
                strcat(tmp, bp->folders[i].subfiles[j].full_name);
                printf("%s\n", tmp);

                fp = fopen(tmp, "wb");
                fwrite(bp->folders[i].subfiles[j].fstp->ptr, 1, bp->folders[i].subfiles[j].fstp->size, fp);
                fclose(fp);
            }
        }
        brres_free(bp);
    }

    return 0;
}
