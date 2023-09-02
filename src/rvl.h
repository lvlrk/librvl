#ifndef RVL_V0_H
#define RVL_V0_H

/************************
 *  _     ___ ____      *
 * | |   |_ _| __ )     *
 * | |    | ||  _ \     *
 * | |___ | || |_) |    *
 * |_____|___|____/     *
 * |  _ \ \   / / |     *
 * | |_) \ \ / /| |     *
 * |  _ < \ V / | |___  *
 * |_| \_\ \_/  |_____| *
 *                      *
 ************************/

// librvl supports the following filetypes:
//
// - .lzs   sszl  (SSZL) from Namco Museum Remix
// - .arc   arcv  (VCRA) from Namco Museum Remix
// - .brres brres (bres) from the Wii Standard Library (in-development)

// version info:
// the current librvl version is displayed at the header guard (RVL_V0_H)
//
// version numbers < 1 or WITH decimals are IN-DEVELOPMENT
// version numbers >= 1 and WITHOUT decimals are STABLE
//
// for example, the current version(v0), is in-development

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <math.h>

/***************************
 *  _        ___     ____  *
 * | |      / _ \   / ___| *
 * | |     | | | | | |  _  *
 * | |___  | |_| | | |_| | *
 * |_____|  \___/   \____| *
 *                         *
 ***************************/

#define INFO(msg) fprintf(stdout, "%s info: *** %s ***\n", __func__, msg)

#define WARN(msg) fprintf(stderr, "%s \033[1;35mwarning\033[0m: *** %s ***\n", __func__, msg)

#define ERROR(msg) fprintf(stderr, "%s \033[1;31merror\033[0m: *** %s ***\n", __func__, msg)
#define ERROR_ALLOC(target) fprintf(stderr, "%s \033[1;31mem error\033[0m: *** could not allocate %s ***\n", __func__, target)
#define ERROR_REALLOC(target) fprintf(stderr, "%s \033[1;31mem error\033[0m: *** could not reallocate %s ***\n", __func__, target)
#define ERROR_BAD(target) fprintf(stderr, "%s \033[1;31mparam error\033[0m: *** bad %s ***\n", __func__, target)

/*******************************************
 *  _____  __   __  ____    _____   ____   *
 * |_   _| \ \ / / |  _ \  | ____| / ___|  *
 *   | |    \ V /  | |_) | |  _|   \___ \  *
 *   | |     | |   |  __/  | |___   ___) | *
 *   |_|     |_|   |_|     |_____| |____/  *
 *                                         *
 *******************************************/

// basic shortened (from c++)
typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;

// basic unsigned
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
// basic signed
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

// unsigned big endian
typedef u16 ube16_t;
typedef u32 ube32_t;
typedef u64 ube64_t;
// signed big endian
typedef s16 be16_t;
typedef s32 be32_t;
typedef s64 be64_t;

// unsigned little endian
typedef u16 ule16_t;
typedef u32 ule32_t;
typedef u64 ule64_t;
// signed little endian
typedef s16 le16_t;
typedef s32 le32_t;
typedef s64 le64_t;

// basic floats
typedef float f32;
typedef double f64;

/****************************************
 *  _____ _   _ ____ ___    _    _   _  *
 * | ____| \ | |  _ \_ _|  / \  | \ | | *
 * |  _| |  \| | | | | |  / _ \ |  \| | *
 * | |___| |\  | |_| | | / ___ \| |\  | *
 * |_____|_| \_|____/___/_/   \_\_| \_| *
 *                                      *
 ****************************************/

// undefine any pre-existing LITTLE_ENDIAN macros
#undef LITTLE_ENDIAN
#define LITTLE_ENDIAN 1234

// undefine any pre-existing BIG_ENDIAN macros
#undef BIG_ENDIAN
#define BIG_ENDIAN 4321

// undefine any pre-existing BYTE_ORDER macros
#undef BYTE_ORDER
// x86-64 and i386 are guaranteed to be little endian
#if (defined __x86_64__) || (defined __i386__)
#define BYTE_ORDER LITTLE_ENDIAN
#else
#define BYTE_ORDER BIG_ENDIAN
#endif

// byteswap a 16-bit integer (short)
u16 bswap_16(u16 x) {
    return ((x << 8) | (x >> 8));
}

// byteswap a 32-bit integer (int)
u32 bswap_32(u32 x) {
    x = ((x << 8) & 0xff00ff00) | ((x >> 8) & 0xff00ff); 
    return ((x << 16) | (x >> 16));
}

// byteswap a 64-bit integer (long)
u64 bswap_64(u64 x) {
    x = ((x << 8) & 0xff00ff00ff00ff00ULL) |
        ((x >> 8) & 0x00ff00ff00ff00ffULL);
    x = ((x << 16) & 0xffff0000ffff0000ULL) |
        ((x >> 16) & 0x0000ffff0000ffffULL);
    return ((x << 32) | (x >> 32));
}

/*******************************************
 *  ____ _____ ____  _____    _    __  __  *
 * / ___|_   _|  _ \| ____|  / \  |  \/  | *
 * \___ \ | | | |_) |  _|   / _ \ | |\/| | *
 *  ___) || | |  _ <| |___ / ___ \| |  | | *
 * |____/ |_| |_| \_\_____/_/   \_\_|  |_| *
 *                                         *
 *******************************************/

// stream of data
// io dependent on position and endianness (byteorder)
// like a FILE*, minus the file part
typedef struct stream {
    void *ptr;      // data pointer          (!= NULL)
    uint size;      // data size             (>= 1)
    uint pos;       // data position         (>= 0)
    uint byteorder; // int-reading byteorder (LITTLE_ENDIAN || BIG_ENDIAN)
} stream_t;

// free the stream and its elements
// returns void
void stream_free(stream_t *stp) {
    if(stp != NULL) {
        if(stp->ptr != NULL) {
            free(stp->ptr);
        } free(stp);
    }
}

// initialize a new stream
// returns a non-NULL stream_t* on success; NULL on failure
stream_t *stream_init(void) {
    stream_t *stp = NULL;
    stp = malloc(sizeof(stream_t));
    if(stp == NULL) {
        ERROR_ALLOC("stream");
        return NULL;
    }
    *stp = (stream_t){NULL, 0, 0, BYTE_ORDER};

    stp->ptr = malloc(0);
    if(stp->ptr == NULL) {
        ERROR_ALLOC("stream->ptr");
        goto error;
    }

    return stp;
error:
    if(stp != NULL) {
        stream_free(stp);
    }

    return NULL;
}

// set the stream's pointer and size to nptr and nsize (respectively)
// returns 0 on success; 1 on failure
int stream_set(stream_t *stp, const void *nptr, uint nsize) {
    if(stp == NULL) {
        ERROR_BAD("stream");
        return 1;
    }

    if(nptr == NULL) {
        ERROR_BAD("new stream ptr");
        return 1;
    }

    if(nsize < 1) {
        ERROR_BAD("new stream ptr size");
        return 1;
    }

    *stp = (stream_t){stp->ptr, nsize, 0, stp->byteorder};

    stp->ptr = realloc(stp->ptr, stp->size);
    if(stp->ptr == NULL) {
        ERROR_REALLOC("new stream->ptr");
        return 1;
    }

    memcpy(stp->ptr, nptr, stp->size);

    return 0;
}

// read a file's contents into the stream
// returns a non-NULL stream_t* on success; NULL on failure
stream_t *stream_read_file(const char *filename) {
    if(filename == NULL) {
        ERROR_BAD("filename");
        return NULL;
    }

    stream_t *stp = stream_init();
    if(stp == NULL) {
        ERROR("could not init stream");
        return NULL;
    }

    FILE *fp = NULL;
    fp = fopen(filename, "rb");
    if(fp == NULL) {
        ERROR("could not open file");
        goto error;
    }

    fseek(fp, 0, SEEK_END);
    stp->size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    stp->ptr = realloc(stp->ptr, stp->size);
    if(stp->ptr == NULL) {
        ERROR_REALLOC("stream->ptr");
        goto error;
    }

    if(fread(stp->ptr, 1, stp->size, fp) != stp->size) {
        ERROR("could not read file");
        goto error;
    }

    fclose(fp);

    return stp;
error:
    if(fp != NULL) {
        fclose(fp);
    }
    if(stp != NULL) {
        stream_free(stp);
    }

    return NULL;
}

// read data from the stream
// returns void
void stream_read(stream_t *stp, void *ptr, uint size) {
    if(stp == NULL) {
        ERROR_BAD("stream");
        return;
    }

    if(ptr == NULL) {
        ERROR_BAD("ptr");
        return;
    }

    // reached EOS; uh oh
    if(stp->pos + size > stp->size) {
        ERROR("reached EOS");
        return;
    }

    memcpy(ptr, (const u8*)stp->ptr + stp->pos, size);
    stp->pos += size;
}

// read an int (endian-dependent) from the stream
// returns void
void stream_read_int(stream_t *stp, void *ptr, uint size) {
    if(stp == NULL) {
        ERROR_BAD("stream");
        return;
    }
    
    if(ptr == NULL) {
        ERROR_BAD("ptr");
        return;
    }

    // reached EOS; uh oh
    if(stp->pos + size > stp->size) {
        ERROR("reached EOS");
        return;
    }

    memcpy(ptr, (const u8*)stp->ptr + stp->pos, size);
    stp->pos += size;

    if(stp->byteorder != BYTE_ORDER) {
        switch(size) {
            case 2:
                *(u16*)ptr = bswap_16(*(u16*)ptr);
                break;
            case 4:
                *(u32*)ptr = bswap_32(*(u32*)ptr);
                break;
            case 8:
                *(u64*)ptr = bswap_64(*(u64*)ptr);
                break;
        }
    }
}

// write the stream to a file
// returns void
void stream_write_file(stream_t *stp, const char *filename) {
    if(stp == NULL) {
        ERROR_BAD("stream");
        return;
    }

    if(filename == NULL) {
        ERROR_BAD("filename");
        return;
    }

    FILE *fp = NULL;
    fp = fopen(filename, "wb");
    if(fp == NULL) {
        ERROR("could not open file");
        return;
    }

    if(fwrite(stp->ptr, 1, stp->size, fp) != stp->size) {
        ERROR("could not write stream");
        goto error;
    }

    fclose(fp);
error:
    if(fp != NULL) {
        fclose(fp);
    }
}

// write data to the stream
// returns void
void stream_write(stream_t *stp, void *ptr, uint size) {
    if(stp == NULL) {
        ERROR_BAD("stream");
        return;
    }

    if(ptr == NULL) {
        ERROR_BAD("ptr");
        return;
    }

    // EOS, so we resize
    if(stp->pos + size > stp->size) {
        stp->ptr = realloc(stp->ptr, stp->size + size);
        if(stp->ptr == NULL) {
            ERROR_REALLOC("stream->ptr");
            return;
        }
    }

    memcpy((u8*)stp->ptr + stp->pos, ptr, size);
    stp->pos += size;
}

// write an int (endian-dependent) to the stream
// returns void
void stream_write_int(stream_t *stp, void *ptr, uint size) {
    if(stp == NULL) {
        ERROR_BAD("stream");
        return;
    }
    
    if(ptr == NULL) {
        ERROR_BAD("ptr");
        return;
    }

    // EOS, so we resize
    if(stp->pos + size > stp->size) {
        stp->ptr = realloc(stp->ptr, stp->size + size);
        if(stp->ptr == NULL) {
            ERROR_REALLOC("stream->ptr");
            return;
        }
    }

    // temp ptr for byteswapping
    void *tptr = ptr;

    // byteorder isnt host byteorder
    if(stp->byteorder != BYTE_ORDER) {
        switch(size) {
            case 2:
                *(u16*)tptr = bswap_16(*(u16*)tptr);
                break;
            case 4:
                *(u32*)tptr = bswap_32(*(u32*)tptr);
                break;
            case 8:
                *(u64*)tptr = bswap_64(*(u64*)tptr);
                break;
        }
    }

    memcpy((u8*)stp->ptr + stp->pos, tptr, size);
    stp->pos += size;
}

/***************************************************************
 *   _   _      _      ____    _   _   _____   ____    _       *
 *  | | | |    / \    / ___|  | | | | |_   _| | __ )  | |      *
 *  | |_| |   / _ \   \___ \  | |_| |   | |   |  _ \  | |      *
 *  |  _  |  / ___ \   ___) | |  _  |   | |   | |_) | | |___   *
 *  |_| |_| /_/   \_\ |____/  |_| |_|   |_|   |____/  |_____|  *
 *                                                             *
 ***************************************************************/

// a simple hashtable implementation
typedef struct hashtable {
    uint n_buckets; // how many buckets [> 0]
    void **buckets; // buckets          (!= NULL)
} hashtable_t;

// free a hashtable and its elements
// returns void
void hashtable_free(hashtable_t *table) {
    if(table != NULL) {
        if(table->buckets != NULL) {
            free(table->buckets);
        } free(table);
    }
}

// create a new hashtable
// returns non-NULL hashtable_t* on success; NULL on failure
hashtable_t *hashtable_init(uint n_buckets) {
    hashtable_t *table = NULL;
    table = malloc(sizeof(hashtable_t));
    if(table == NULL) {
        ERROR_ALLOC("hashtable");
        return NULL;
    }

    *table = (hashtable_t){n_buckets, NULL};

    table->buckets = malloc(sizeof(void*) * table->n_buckets);
    if(table->buckets == NULL) {
        ERROR_ALLOC("hashtable->buckets");
        goto error;
    }

    for(uint i = 0; i < table->n_buckets; i++) table->buckets[i] = NULL;

    return table;
error:
    if(table != NULL) {
        hashtable_free(table);
    }

    return NULL;
}

// hashtable hash function: addmul
// returns non -1 on success; -1 on failure
int hashtable_hash_addmul(hashtable_t *table, const char *key) {
    if(table == NULL) {
        ERROR_BAD("hashtable");
        return -1;
    }

    if(key == NULL) {
        ERROR_BAD("hashtable new key");
        return -1;
    }

    uint idx = 0;

    for(uint i = 0; i < strlen(key); i++) {
        for(int j = 0; j < 2; j++) {
            idx += key[i];
            idx *= key[i];
        }
    }

    return idx % table->n_buckets;
}

// hashtable hash function: pow
// this function uses pow(), which is why
// we need to link with -lm
// returns non -1 on success; -1 on failure
int hashtable_hash_pow(hashtable_t *table, const char *key) {
    if(table == NULL) {
        ERROR_BAD("hashtable");
        return -1;
    }

    if(key == NULL) {
        ERROR_BAD("hashtable new key");
        return -1;
    }

    uint idx = 0;

    for(uint i = 0; i < strlen(key); i++) {
        idx += key[i];
        idx *= key[i];

        for(uint j = 0; j < strlen(key); j++) {
            pow(idx, j);
        }
    }

    return idx % table->n_buckets;
}

// hashtable key-hashing callback
// options:
// - hashtable_hash_addmul
// - hashtable_hash_pow
int (*hashtable_hash)(hashtable_t*, const char*) = hashtable_hash_addmul;

// put a value into a hashtable via a key
// returns 0 on success; 1 on failure
int hashtable_put(hashtable_t *table, const char *key, const void *value) {
    if(table == NULL) {
        ERROR_BAD("hashtable");
        return 1;
    }

    if(key == NULL) {
        ERROR_BAD("new hashtable key");
        return 1;
    }

    if(value == NULL) {
        ERROR_BAD("new hashtable value");
        return 1;
    }

    int i = hashtable_hash(table, key);
    if(i == -1) {
        ERROR_BAD("hashtable index");
        return 1;
    }

    if(table->buckets[i] != NULL) {
        ERROR("hashtable collision");
        return 1;
    }

    table->buckets[i] = (void*)value;

    return 0;
}

// get a value in a hashtable via its key
// returns non-NULL const void* on success; NULL on failure
const void *hashtable_get(hashtable_t *table, const char *key) {
    if(table == NULL) {
        ERROR_BAD("hashtable");
        return NULL;
    }

    if(key == NULL) {
        ERROR_BAD("hashtable key");
        return NULL;
    }

    int i = hashtable_hash(table, key);
    if(i == -1) {
        ERROR_BAD("hashtable index");
        return NULL;
    }

    const void *value = table->buckets[i];
    if(value == NULL) {
        ERROR("key does not point to a value");
        return NULL;
    }

    return value;
}

// resize the hashtable's buckets
// returns 0 on success; 1 on failure
int hashtable_resize(hashtable_t *table, uint nn_buckets) {
    if(nn_buckets < table->n_buckets) {
        WARN("possible loss of data");
    } else if(nn_buckets == table->n_buckets) {
        WARN("useless resize");
    }

    table->n_buckets = nn_buckets;
    table->buckets = realloc(table->buckets, sizeof(void*) * table->n_buckets);
    if(table->buckets == NULL) {
        ERROR_REALLOC("hashtable->buckets");
        return 1;
    }

    return 0;
}

/***********************************
 *  ____  ____  ____  _____ ____   *
 * | __ )|  _ \|  _ \| ____/ ___|  *
 * |  _ \| |_) | |_) |  _| \___ \  *
 * | |_) |  _ <|  _ <| |___ ___) | *
 * |____/|_| \_\_| \_\_____|____/  *
 *                                 *
 ***********************************/

typedef struct brres_header {
    char magic[4];      // = "bres"
    uchar bom[2];       // = "\xfe\xff" for big endian,
                        // other for little endian
                        // (rarely not big endian)
    short bom_padding;  // = 0
    ube32_t size;       // file size
    ube16_t root_off;   // offset to root section
    ube16_t n_sections; // how many sections (including root)
} __attribute__((packed)) brres_header_t;

typedef struct brres_entry {
    ube16_t id;        // binary search tree key
    ube16_t unknown;   // usually 0
    ube16_t left_idx;  // decides left placement of node
    ube16_t right_idx; // decides right placement of node
    ube32_t name_off;  // offset to name + start of group
    ube32_t data_off;  // offset to data + start of group
} __attribute__((packed)) brres_entry_t;

typedef struct brres_group {
    ube32_t size;           // size of group section
    ube32_t n_entries;      // how many real entries
    brres_entry_t *entries; // entries[n_entries + 1];
                            // entries[0] is the tree root
} __attribute__((packed)) brres_group_t;

typedef struct brres_root_header {
    char magic[4];         // = "root"
    ube32_t size;          // size of root section
} __attribute__((packed)) brres_root_header_t;

typedef struct brres_root {
    brres_group_t *groups; // groups[0] are folders,
                           // rest are files
} __attribute__((packed)) brres_root_t;

typedef struct brres_info {
    uint          group_start; // the offset of group.size
    brres_group_t group;       // the group
} brres_info_t;

typedef struct brres_subfile {
    char *name;      // name in-file
    char *full_name; // name in-file with extension
    stream_t *fstp;  // subfile stream
} brres_subfile_t;

typedef struct brres_folder {
    char *name;                // name in-file
    uint n_subfiles;           // how many subfiles
    brres_subfile_t *subfiles; // subfiles
} brres_folder_t;

typedef struct brres {
    uint n_folders;          // how many folders
    brres_folder_t *folders; // folders
} brres_t;

typedef struct brres_subfile_header {
    char magic[4]; // = "MDL0"
    ube32_t size;
    ube32_t version;
    be32_t outer_off;
    be32_t *section_offs;
    be32_t name_off;
} brres_subfile_header_t;

enum brres_subtype {
    BR_MDL, // model                            (3DModels(NW4R))
    BR_TEX, // texture                          (Textures(NW4R))
    BR_SRT, // texture movement animations      (AnmTexSrt(NW4R))
    BR_CHR, // model bone animations            (AnmChr(NW4R))
    BR_PAT, // texture swap animations          (AnmTexPat(NW4R))
    BR_CLR, // model vertex color animations    (AnmClr(NW4R))
    BR_SHP, // model polygon animations         (AnmShp(NW4R))
    BR_PLT, // texture palettes                 (Palettes(NW4R))
    BR_VIS, // model bone visibility animations (AnmVis(NW4R))
    BR_SCN  // live-rendered video information  (AnmScn(NW4R))
};

// free a brres and its elements
// returns void
void brres_free(brres_t *bp) {
    if(bp != NULL) {
        if(bp->folders != NULL) {
            for(uint i = 0; i < bp->n_folders; i++) {
                if(bp->folders[i].subfiles != NULL) {
                    for(uint j = 0; j < bp->folders[i].n_subfiles; j++) {
                        if(bp->folders[i].subfiles[j].name != NULL) {
                            free(bp->folders[i].subfiles[j].name);
                        }
                        if(bp->folders[i].subfiles[j].full_name != NULL) {
                            free(bp->folders[i].subfiles[j].full_name);
                        }
                        if(bp->folders[i].subfiles[j].fstp != NULL) {
                            stream_free(bp->folders[i].subfiles[j].fstp);
                        }
                    }

                    free(bp->folders[i].subfiles);
                }
            }

            free(bp->folders);
        }

        free(bp);
    }
}

// initialize a new brres
// returns non-NULL brres_t* on success; NULL on failure
brres_t *brres_init(void) {
    brres_t *bp = NULL;

    bp = malloc(sizeof(brres_t));
    if(bp == NULL) {
        ERROR_ALLOC("brres");
        return NULL;
    }

    *bp = (brres_t){0, NULL};
    bp->folders = malloc(0);
    if(bp->folders == NULL) {
        ERROR_ALLOC("brres->folders");
        goto error;
    }

    return bp;
error:
    if(bp != NULL) brres_free(bp);

    return NULL;
}

// read a brres_info_t from a stream
// returns non-NULL brres_info_t* on success; NULL on failure
brres_info_t *brres_read_info(stream_t *stp) {
    if(stp == NULL) {
        ERROR_BAD("stream");
        return NULL;
    }

    // bip is a funny name
    brres_info_t *bip = NULL;
    bip = malloc(sizeof(brres_info_t));
    if(bip == NULL) {
        ERROR_BAD("brres info");
        return NULL;
    }
    *bip = (brres_info_t){0, {0}};

    bip->group_start = stp->pos;

    stream_read_int(stp, &bip->group.size, 4);
    stream_read_int(stp, &bip->group.n_entries, 4);

    bip->group.entries = malloc(sizeof(brres_entry_t) * bip->group.n_entries);
    if(bip->group.entries == NULL) {
        ERROR_ALLOC("brres info->entries");
        goto error;
    }

    stp->pos += sizeof(brres_entry_t); // skip root entry
    for(uint i = 0; i < bip->group.n_entries; i++) {
        stream_read_int(stp, &bip->group.entries[i].id, 2);
        stream_read_int(stp, &bip->group.entries[i].unknown, 2);
        stream_read_int(stp, &bip->group.entries[i].left_idx, 2);
        stream_read_int(stp, &bip->group.entries[i].right_idx, 2);
        stream_read_int(stp, &bip->group.entries[i].name_off, 4);
        stream_read_int(stp, &bip->group.entries[i].data_off, 4);
    }

    return bip;
error:
    if(bip != NULL) {
        if(bip->group.entries != NULL) {
            free(bip->group.entries);
        } free(bip);
    }

    return NULL;
}

// all arrays ordered based off Custom Mario Kart Wiki
#define BRRES_SUBTYPE_COUNT 9
static const char *brres_subtypes[BRRES_SUBTYPE_COUNT] =
    {"3DModels(NW4R)", "Textures(NW4R)", "AnmTexSrt(NW4R)",
     "AnmChr(NW4R)", "AnmTexPat(NW4R)", "AnmClr(NW4R)",
     "AnmShp(NW4R)", "Palettes(NW4R)", "AnmVis(NW4R)"};

static const char *brres_extensions[BRRES_SUBTYPE_COUNT] =
    {".brmdl", ".brtex", ".brsrt",
     ".brchr", ".brpat", ".brclr",
     ".brshp", ".brplt", ".brvis"};

static const char *brres_magics[BRRES_SUBTYPE_COUNT] =
    {"MDL0", "TEX0", "SRT0",
     "CHR0", "PAT0", "CLR0",
     "SHP0", "PLT0", "VIS0"};

// return the brres-subtype string
// based off of the magic number
// returns non-NULL const char* on success; NULL on failure
const char *brres_subtype_magic(const char magic[4]) {
    hashtable_t *table = hashtable_init(0xff);
    if(table == NULL) {
        ERROR("could not init hashtable");
        return NULL;
    }

    for(uint i = 0; i < BRRES_SUBTYPE_COUNT; i++) {
        hashtable_put(table, brres_magics[i], brres_subtypes[i]);
    }

    return hashtable_get(table, magic);
}

// return the brres-subtype file extension string
// based off of the magic number
// returns non-NULL const char* on success; NULL on failure
const char *brres_extension_magic(const char magic[4]) {
    hashtable_t *table = hashtable_init(0xff);
    if(table == NULL) {
        ERROR("could not init hashtable");
        return NULL;
    }

    for(uint i = 0; i < BRRES_SUBTYPE_COUNT; i++) {
        hashtable_put(table, brres_magics[i], brres_extensions[i]);
    }

    return hashtable_get(table, magic);
}

// reads a brres from a data pointer
// returns non-NULL brres_t* on success; NULL on failure
brres_t *brres_read(const u8 *data, uint size) {
    if(data == NULL) {
        ERROR_BAD("data");
        return NULL;
    }
    
    if(size < 1) {
        ERROR_BAD("size");
        return NULL;
    }

    brres_t *bp = brres_init();
    if(bp == NULL) {
        ERROR("could not init brres");
        return NULL;
    }

    brres_info_t *bfolders = NULL;
    brres_info_t *bfile = NULL;

    stream_t *stp = stream_init();
    if(stp == NULL) {
        ERROR("could not init stream");
        goto error;
    }

    if(stream_set(stp, data, size) == 1) {
        ERROR("could not set stream");
        goto error;
    }

    // read non-endian-dependent members of brres header
    brres_header_t bh = {{0}, {0}, 0, 0, 0, 0};
    stream_read(stp, &bh, 8);

    // check magic
    if(memcmp(bh.magic, "bres", 4)) {
        ERROR("not a brres");
        goto error;
    }

    // check byteorder
    // bom is RARELY never "\xfe\xff"
    if(!memcmp(bh.bom, "\xfe\xff", 2)) {
        stp->byteorder = BIG_ENDIAN;
    } else {
        stp->byteorder = LITTLE_ENDIAN;
    }

    // read rest of brres header
    stream_read_int(stp, &bh.size, sizeof(bh.size));
    stream_read_int(stp, &bh.root_off, sizeof(bh.root_off));
    stream_read_int(stp, &bh.n_sections, sizeof(bh.n_sections));

    // read brres root header
    brres_root_header_t brh = {{0}, 0};
    stream_read(stp, brh.magic, 4);
    stream_read_int(stp, &brh.size, 4);

    // read first group; aka the folder entries
    bfolders = brres_read_info(stp);
    if(bfolders == NULL) {
        ERROR("could not read brres binary folders");
        goto error;
    }

    bp->n_folders = bfolders->group.n_entries;
    bp->folders = malloc(sizeof(brres_folder_t) * bp->n_folders);
    if(bp->folders == NULL) {
        ERROR_ALLOC("brres->folders");
        goto error;
    }

    uint fname_len, sfname_len, sfdata_len;
    char magic[4];
    const char *extension = NULL;
    for(uint i = 0; i < bp->n_folders; i++) {
        // USUALLY there is ONE file per folder
        bp->folders[i].n_subfiles = bfolders->group.n_entries;
        bp->folders[i].subfiles = malloc(sizeof(brres_subfile_t) * bp->folders[i].n_subfiles);
        if(bp->folders[i].subfiles == NULL) {
            ERROR_ALLOC("brres->folders[*]->subfiles");
            goto error;
        }

        // goto position of folder name
        stp->pos = bfolders->group.entries[i].name_off + bfolders->group_start - 4;
        stream_read_int(stp, &fname_len, 4);

        bp->folders[i].name = malloc(fname_len + 1);
        if(bp->folders[i].name == NULL) {
            ERROR_ALLOC("brres->folders[*]->name");
            goto error;
        }

        memset(bp->folders[i].name, 0, fname_len + 1);
        stream_read(stp, bp->folders[i].name, fname_len);

        // goto position of folder's file(s) entry(s)
        stp->pos = bfolders->group.entries[i].data_off + bfolders->group_start;

        // read folder's file group/info
        bfile = brres_read_info(stp);
        if(bfile == NULL) {
            ERROR("could not read brres binary file");
            goto error;
        }

        bp->folders[i].n_subfiles = bfile->group.n_entries;
        for(uint j = 0; j < bp->folders[i].n_subfiles; j++) {
            // goto position of file's name
            stp->pos = bfile->group.entries[j].name_off + bfile->group_start - 4;

            stream_read_int(stp, &sfname_len, 4);

            bp->folders[i].subfiles[j].name = malloc(sfname_len + 1);
            if(bp->folders[i].subfiles[j].name == NULL) {
                ERROR_ALLOC("brres->folders[*].subfiles[*].name");
                goto error;
            }

            memset(bp->folders[i].subfiles[j].name, 0, sfname_len + 1);
            stream_read(stp, bp->folders[i].subfiles[j].name, sfname_len);

            // set full name
            bp->folders[i].subfiles[j].full_name = malloc(sfname_len + 7);
            if(bp->folders[i].subfiles[j].full_name == NULL) {
                ERROR_ALLOC("brres->folders[*].subfiles[*].full_name");
                goto error;
            }

            memset(bp->folders[i].subfiles[j].full_name, 0, sfname_len + 7);
            memcpy(bp->folders[i].subfiles[j].full_name, bp->folders[i].subfiles[j].name, sfname_len);
            
            // goto file data position
            stp->pos = bfile->group.entries[j].data_off + bfile->group_start;
            stream_read(stp, magic, 4);
            extension = brres_extension_magic(magic);
            if(extension == NULL) {
                ERROR("could not get brres extension from magic");
                goto error;
            }

            // append extension
            strncat(bp->folders[i].subfiles[j].full_name, brres_extension_magic(magic), 7);

            stream_read_int(stp, &sfdata_len, 4);

            if(bp->folders[i].subfiles[j].fstp == NULL) {
                bp->folders[i].subfiles[j].fstp = stream_init();
                if(bp->folders[i].subfiles[j].fstp == NULL) {
                    ERROR("could not init stream");
                    goto error;
                }
            }

            bp->folders[i].subfiles[j].fstp->byteorder = stp->byteorder;

            // set stream for subfile
            if(stream_set(bp->folders[i].subfiles[j].fstp,
                          (u8*)stp->ptr + bfile->group.entries[j].data_off
                          + bfile->group_start, sfdata_len) == 1) {
                ERROR("could not set stream");
                goto error;
            }
        }

        if(bfile->group.entries != NULL) {
            free(bfile->group.entries);
        } free(bfile);

    }

    if(bfolders->group.entries != NULL) {
        free(bfolders->group.entries);
    } free(bfolders);

    return bp;
error:
    if(bp != NULL) brres_free(bp);
    if(bfile != NULL) {
        if(bfile->group.entries != NULL) {
            free(bfile->group.entries);
        } free(bfile);
    }
    if(bfolders != NULL) {
        if(bfolders->group.entries != NULL) {
            free(bfolders->group.entries);
        } free(bfolders);
    }

    return NULL;
}

// read brres from stream
// returns non-NULL brres_t* on success; NULL on failure
brres_t *brres_read_stream(stream_t *stp) {
    if(stp == NULL) {
        ERROR_BAD("stream");
        return NULL;
    }

    return brres_read(stp->ptr, stp->size);
}

// read brres from file
// returns non-NULL brres_t* on success; NULL on failure
brres_t *brres_read_file(const char *filename) {
    if(filename == NULL) {
        ERROR_BAD("filename");
        return NULL;
    }

    stream_t *stp = stream_read_file(filename);
    if(stp == NULL) {
        ERROR("could not init stream");
        return NULL;
    }

    return brres_read_stream(stp);
}

// print brres members
// returns void
void brres_print(brres_t *bp) {
    puts("/");

    for(uint i = 0; i < bp->n_folders; i++) {
        printf("L %s\n", bp->folders[i].name);
        for(uint j = 0; j < bp->folders[i].n_subfiles; j++) {
            printf("  L %s\n", bp->folders[i].subfiles[j].full_name);
        }
    }
}

/*****************************************
 *      _      ____     ____  __     __  *
 *     / \    |  _ \   / ___| \ \   / /  *
 *    / _ \   | |_) | | |      \ \ / /   *
 *   / ___ \  |  _ <  | |___    \ V /    *
 *  /_/   \_\ |_| \_\  \____|    \_/     *
 *                                       *
 *****************************************/

typedef struct arcv_header {
    char magic[4];     // = "VCRA"          (== "VCRA")
    ule32_t n_members; // how many members  [> 0]
    ule32_t size;      // file size         (> sizeof(arcv_header_t))
    int zero;          // = 0               [== 0]
    ule32_t unknown;   // = 0x20070205      [== 0x20070205]
    char padding[44];  // = (char)0[56]     [== (char)0[56]]
} __attribute__((packed)) arcv_header_t;

typedef struct arcv_member_info {
    ule32_t off;   // file data offset (> (sizeof(arcv_header_t) +
    //                  (sizeof(arcv_member_info_t) *
    //                  arcv_header_t.n_members)))
    ule32_t size;  // file data size   [> 0]
    char name[56]; // filename         (!= (char)0[56])
} __attribute__((packed)) arcv_member_info_t;

typedef struct arcv_member {
    char *name; // filename        (!= NULL)
    uint size;  // file data size  [> 0]
    u8 *data;   // file data       (!= NULL)
} arcv_member_t;

typedef struct arcv {
    uint n_members;         // how many members     [> 0]
    arcv_member_t *members; // members array        (!= NULL)

    // table of member names; for arcv_member_get() (!= NULL)
    hashtable_t *member_name_table;
} arcv_t;

void arcv_free(arcv_t *ap) {
    if(ap != NULL) {
        if(ap->members != NULL) {
            for(uint i = 0; i < ap->n_members; i++) {
                if(ap->members[i].name != NULL) {
                    free(ap->members[i].name);
                }
                if(ap->members[i].data != NULL) {
                    free(ap->members[i].data);
                }
            }

            free(ap->members);
        }

        if(ap->member_name_table != NULL) {
            hashtable_free(ap->member_name_table);
        }

        free(ap);
    }
}

// initialize an arcv
// returns non-NULL arcv_t* on success; NULL on failure
arcv_t *arcv_init(void) {
    arcv_t *ap = NULL;
    ap = malloc(sizeof(arcv_t));
    if(ap == NULL) {
        ERROR_ALLOC("arcv");
        return NULL;
    }
    *ap = (arcv_t){0, NULL, NULL};

    ap->members = malloc(0);
    if(ap->members == NULL) {
        ERROR_ALLOC("arcv->members");
        goto error;
    }

    ap->member_name_table = hashtable_init(0xffff);
    if(ap->member_name_table == NULL) {
        ERROR("could not init arcv->member name hashtable");
        goto error;
    }

    return ap;
error:
    if(ap != NULL) {
        arcv_free(ap);
    }

    return NULL;
}

// reads an arcv from a data pointer
// returns non-NULL arcv_t* on success; NULL on failure
arcv_t *arcv_read(const u8 *data, uint size) {
    if(data == NULL) {
        ERROR_BAD("data");
        return NULL;
    }

    if(size < 1) {
        ERROR_BAD("size");
        return NULL;
    }

    arcv_t *ap = arcv_init();
    if(ap == NULL) {
        ERROR("could not init arcv");
        return NULL;
    }

    stream_t *stp = stream_init();
    if(stp == NULL) {
        ERROR("could not init stream");
        goto error;
    }

    if(stream_set(stp, data, size) == 1) {
        ERROR("could not set stream");
        goto error;
    }

    arcv_header_t ah = (arcv_header_t){{0}, 0, 0, 0, 0, {0}};
    stream_read(stp, &ah, sizeof(arcv_header_t));

    if(memcmp(ah.magic, "VCRA", 4)) {
        ERROR("not an arcv");
        goto error;
    }

    ap->n_members = ah.n_members;
    ap->members = realloc(ap->members, sizeof(arcv_member_t) * ap->n_members);
    if(ap->members == NULL) {
        ERROR_REALLOC("arcv->members");
        goto error;
    }

    arcv_member_info_t member_info;
    for(uint i = 0; i < ap->n_members; i++) {
        // initialize structures
        member_info = (arcv_member_info_t){0, 0, {0}};

        ap->members[i] = (arcv_member_t){NULL, 0, NULL};
        ap->members[i].name = malloc(0);
        if(ap->members[i].name == NULL) {
            ERROR_ALLOC("arcv->members[*].name");
            goto error;
        }

        ap->members[i].data = malloc(0);
        if(ap->members[i].data == NULL) {
            ERROR_ALLOC("arcv->member[*].data");
            goto error;
        }

        // read member info
        stream_read(stp, &member_info, sizeof(arcv_member_info_t));

        ap->members[i].name = realloc(ap->members[i].name, 256);
        if(ap->members[i].name == NULL) {
            ERROR_REALLOC("arcv->members[*].name");
            goto error;
        }
        strncpy(ap->members[i].name, member_info.name, 56);

        ap->members[i].size = member_info.size;

        ap->members[i].data = realloc(ap->members[i].data, ap->members[i].size);
        if(ap->members[i].data == NULL) {
            ERROR_REALLOC("arcv->members[*].data");
            goto error;
        }

        memcpy(ap->members[i].data, (const u8*)stp->ptr + member_info.off, ap->members[i].size);

        if(hashtable_put(ap->member_name_table, ap->members[i].name, &ap->members[i]) == 1) {
            goto error;
        }
    }

    return ap;
error:
    if(ap != NULL) {
        arcv_free(ap);
    }

    return NULL;
}

// reads an arcv from a stream
// returns non-NULL arcv_t* on success; NULL on failure
arcv_t *arcv_read_stream(stream_t *stp) {
    return arcv_read(stp->ptr, stp->size);
}

// reads an arcv from a file
// returns non-NULL arcv_t* on success; NULL on failure
arcv_t *arcv_read_file(const char *filename) {
    stream_t *stp = stream_read_file(filename);
    if(stp == NULL) {
        ERROR("could not init stream");
        return NULL;
    }

    return arcv_read_stream(stp);
}

/**********************************
 *  _       _____  ____    ____   *
 * | |     |__  / / ___|  / ___|  *
 * | |       / /  \___ \  \___ \  *
 * | |___   / /_   ___) |  ___) | *
 * |_____| /____| |____/  |____/  *
 *                                *
 **********************************/

// NOTE: code from the lzss module
//       is older and taken/modified from
//       an older version of QuickBMS

typedef struct lzss_param {
    // NOTE: EI + EJ MUST equal 16
    int EI;       // = 10..12;   reference offset bits size
    int EJ;       // = 6..4;     reference length bits size
    int P;        // = 2;        reference bytes size
    int rless;    // = P
    int init_chr; // = ' ' or 0; initial character in code/text buffer
} lzss_param_t;

#define LZSS_PARAM (lzss_param_t){12, 4, 2, 2, ' '}
#define LZSS0_PARAM (lzss_param_t){12, 4, 2, 2, 0}

enum lzss_window_param {
    LZS_VESPERIA = -1, // from Tales of Vesperia
    LZS_INC = -2,      // window[i] = i (increasing)
    LZS_DEC = -3       // window[i] = i (decreasing)
};

// initialize search window
void lzss_set_window(u8 *window, int window_size, int init_chr) {
    int i, n;
    i = n = 0;

    switch(init_chr) {
        case LZS_VESPERIA:    // Tales of Vesperia (thanks to delguoqing)
            memset(window, 0, window_size);
            for(;; i++) {
                n = (i * 8) + 6;
                if(n >= window_size) break;
                window[n] = i;
            }
            break;
        case LZS_INC:    // invented
            for(; i < window_size; i++) window[i] = i;
            break;
        case LZS_DEC:    // invented
            for(i = window_size - 1; i >= 0; i--) window[i] = i;
            break;
        default:
            memset(window, init_chr, window_size);
            break;
    }
}

// decompress compressed source data(src)[srclen]
// to decompressed destination data(dst)[dstlen]
//
// NOTE: dstlen can equal srclen because dst
//       will always be smaller than src
//
// returns decompressed data size
uint unlzss(u8 *src, uint srclen, u8 *dst, uint dstlen, lzss_param_t param) {
    // (EI + EJ == 16)
    int EI = param.EI;
    int EJ = param.EJ;
    int P  = param.P;
    int N; // ring buffer size
    int F; // max reference seek-back size
    int rless = param.rless;
    int init_chr = param.init_chr;

    static int slide_winsz = 0;
    static unsigned char *slide_win = NULL;
    unsigned char *dststart = dst;
    unsigned char *srcend = src + srclen;
    unsigned char *dstend = dst + dstlen;
    int  i, j, k, r, c;
    unsigned flags;

    N = 1 << EI;
    F = 1 << EJ;

    if(N > slide_winsz) {
        slide_win = realloc(slide_win, N);
        if(!slide_win) return -1;
        slide_winsz = N;
    }
    lzss_set_window(slide_win, N, init_chr);

    dst = dststart;
    srcend = src + srclen;
    r = (N - F) - rless;
    N--; F--;

    for(flags = 0;; flags >>= 1) {
        if(!(flags & 0x100)) {
            if(src >= srcend) break;
            flags = *src++;
            flags |= 0xff00;
        }
        if(flags & 1) {
            if(src >= srcend) break;
            c = *src++;
            if(dst >= dstend) goto quit; //return -1; better?
            *dst++ = c;
            slide_win[r] = c;
            r = (r + 1) & N;
        } else {
            if(src >= srcend) break;
            i = *src++;
            if(src >= srcend) break;
            j = *src++;
            i |= ((j >> EJ) << 8);
            j  = (j & F) + P;
            for(k = 0; k <= j; k++) {
                c = slide_win[(i + k) & N];
                if(dst >= dstend) goto quit; //return -1; better?
                *dst++ = c;
                slide_win[r] = c;
                r = (r + 1) & N;
            }
        }
    }
quit:
    return(dst - dststart);
}

int N =      4096; // size of ring buffer
int F =        18; // upper limit for match_length
int THRESHOLD = 2; /* encode string into position and length
                      if match_length is greater than this */
int NIL;           // index for root of binary search trees

unsigned int
textsize = 0,   /* text size counter */
codesize = 0;   /* code size counter */
static unsigned char *text_buf = NULL;  /* ring buffer of size N,
            with extra F-1 bytes to facilitate string comparison */
int     match_position, match_length;  /* of longest match.  These are
            set by the InsertNode() procedure. */
static int  *lson = NULL,
*rson = NULL,
*dad  = NULL;
/* left & right children &
            parents -- These constitute binary search trees. */

static
unsigned char   *infile   = NULL,
*infilel  = NULL,
*outfile  = NULL,
*outfilel = NULL;

int lzss_xgetc(void) {
    if(infile >= infilel) return -1;
    return(*infile++);
}

int lzss_xputc(int chr) {
    if(outfile >= outfilel) return -1;
    *outfile++ = chr;
    return(chr);
}

void InitTree(void)  /* initialize trees */
{
    int  i;

    /* For i = 0 to N - 1, rson[i] and lson[i] will be the right and
       left children of node i.  These nodes need not be initialized.
       Also, dad[i] is the parent of node i.  These are initialized to
       NIL (= N), which stands for 'not used.'
       For i = 0 to 255, rson[N + i + 1] is the root of the tree
       for strings that begin with character i.  These are initialized
       to NIL.  Note there are 256 trees. */

    for (i = N + 1; i <= N + 256; i++) rson[i] = NIL;
    for (i = 0; i < N; i++) dad[i] = NIL;
}

void InsertNode(int r)
/* Inserts string of length F, text_buf[r..r+F-1], into one of the
       trees (text_buf[r]'th tree) and returns the longest-match position
       and length via the global variables match_position and match_length.
       If match_length = F, then removes the old node in favor of the new
       one, because the old one will be deleted sooner.
       Note r plays double role, as tree node and position in buffer. */
{
    int  i, p, cmp;
    unsigned char  *key;

    cmp = 1;  key = &text_buf[r];  p = N + 1 + key[0];
    rson[r] = lson[r] = NIL;  match_length = 0;
    for ( ; ; ) {
        if (cmp >= 0) {
            if (rson[p] != NIL) p = rson[p];
            else {  rson[p] = r;  dad[r] = p;  return;  }
        } else {
            if (lson[p] != NIL) p = lson[p];
            else {  lson[p] = r;  dad[r] = p;  return;  }
        }
        for (i = 1; i < F; i++)
            if ((cmp = key[i] - text_buf[p + i]) != 0)  break;
        if (i > match_length) {
            match_position = p;
            if ((match_length = i) >= F)  break;
        }
    }
    dad[r] = dad[p];  lson[r] = lson[p];  rson[r] = rson[p];
    dad[lson[p]] = r;  dad[rson[p]] = r;
    if (rson[dad[p]] == p) rson[dad[p]] = r;
    else                   lson[dad[p]] = r;
    dad[p] = NIL;  /* remove p */
}

void DeleteNode(int p)  /* deletes node p from tree */
{
    int  q;

    if (dad[p] == NIL) return;  /* not in tree */
    if (rson[p] == NIL) q = lson[p];
    else if (lson[p] == NIL) q = rson[p];
    else {
        q = lson[p];
        if (rson[q] != NIL) {
            do {  q = rson[q];  } while (rson[q] != NIL);
            rson[dad[q]] = lson[q];  dad[lson[q]] = dad[q];
            lson[q] = lson[p];  dad[lson[p]] = q;
        }
        rson[q] = rson[p];  dad[rson[p]] = q;
    }
    dad[q] = dad[p];
    if (rson[dad[p]] == p) rson[dad[p]] = q;  else lson[dad[p]] = q;
    dad[p] = NIL;
}

void Encode(int init_chr)
{
    int  i, c, len, r, s, last_match_length, code_buf_ptr;
    unsigned char  code_buf[17], mask;

    InitTree();  /* initialize trees */
    code_buf[0] = 0;  /* code_buf[1..16] saves eight units of code, and
        code_buf[0] works as eight flags, "1" representing that the unit
        is an unencoded letter (1 byte), "0" a position-and-length pair
        (2 bytes).  Thus, eight units require at most 16 bytes of code. */
    code_buf_ptr = mask = 1;
    s = 0;  r = N - F;
    //for (i = s; i < r; i++) text_buf[i] = init_chr;  /* Clear the buffer with
    //  any character that will appear often. */
    lzss_set_window(text_buf, r, init_chr);

    for (len = 0; len < F && (c = lzss_xgetc()) != EOF; len++)
        text_buf[r + len] = c;  /* Read F bytes into the last F bytes of
            the buffer */
    if ((textsize = len) == 0) return;  /* text of size zero */
    for (i = 1; i <= F; i++) InsertNode(r - i);  /* Insert the F strings,
        each of which begins with one or more 'space' characters.  Note
        the order in which these strings are inserted.  This way,
        degenerate trees will be less likely to occur. */
    InsertNode(r);  /* Finally, insert the whole string just read.  The
        global variables match_length and match_position are set. */
    do {
        if (match_length > len) match_length = len;  /* match_length
            may be spuriously long near the end of text. */
        if (match_length <= THRESHOLD) {
            match_length = 1;  /* Not long enough match.  Send one byte. */
            code_buf[0] |= mask;  /* 'send one byte' flag */
            code_buf[code_buf_ptr++] = text_buf[r];  /* Send uncoded. */
        } else {
            code_buf[code_buf_ptr++] = (unsigned char) match_position;
            code_buf[code_buf_ptr++] = (unsigned char)
                (((match_position >> 4) & 0xf0)
                | (match_length - (THRESHOLD + 1)));  /* Send position and
                    length pair. Note match_length > THRESHOLD. */
        }
        if ((mask <<= 1) == 0) {  /* Shift mask left one bit. */
            for (i = 0; i < code_buf_ptr; i++)  /* Send at most 8 units of */
                lzss_xputc(code_buf[i]);     /* code together */
            codesize += code_buf_ptr;
            code_buf[0] = 0;  code_buf_ptr = mask = 1;
        }
        last_match_length = match_length;
        for (i = 0; i < last_match_length &&
        (c = lzss_xgetc()) != EOF; i++) {
            DeleteNode(s);      /* Delete old strings and */
            text_buf[s] = c;    /* read new bytes */
            if (s < F - 1) text_buf[s + N] = c;  /* If the position is
                near the end of buffer, extend the buffer to make
                string comparison easier. */
            s = (s + 1) & (N - 1);  r = (r + 1) & (N - 1);
            /* Since this is a ring buffer, increment the position
            modulo N. */
            InsertNode(r);  /* Register the string in text_buf[r..r+F-1] */
        }
        while (i++ < last_match_length) {   /* After the end of text, */
            DeleteNode(s);                  /* no need to read, but */
            s = (s + 1) & (N - 1);  r = (r + 1) & (N - 1);
            if (--len) InsertNode(r);       /* buffer may not be empty. */
        }
    } while (len > 0); //until length of string to be processed is zero
    if (code_buf_ptr > 1) { // Send remaining code.
        for (i = 0; i < code_buf_ptr; i++) lzss_xputc(code_buf[i]);
        codesize += code_buf_ptr;
    }
}

// compress uncompressed source data(in)[insz]
// to compressed destination data(out)[outsz]
//
// returns compressed data size
uint lzss_compress(u8 *in, uint insz, u8 *out, uint outsz, lzss_param_t param) {
    infile   = in;
    infilel  = in + insz;
    outfile  = out;
    outfilel = out + outsz;

    NIL = N;
    text_buf = realloc(text_buf, N + F - 1);
    lson     = realloc(lson, sizeof(int) * (N + 1));
    rson     = realloc(rson, sizeof(int) * (N + 257));
    dad      = realloc(dad,  sizeof(int) * (N + 1));

    Encode(param.init_chr);
    return(outfile - out);
}

/**********************************
 *   ____    ____    _____  _     *
 * / ___|  / ___|  |__  / | |     *
 * \___ \  \___ \    / /  | |     *
 *  ___) |  ___) |  / /_  | |___  *
 * |____/  |____/  /____| |_____| *
 *                                *
 **********************************/

// Namco Museum Remix .lzs file

typedef struct sszl_header {
    char magic[4];             // = "SSZL"                  (== "SSZL")
    int zero;                  // = 0                       [== 0]
    ule32_t compressed_size;   // size of compressed data   (> 0)
    ule32_t uncompressed_size; // size of uncompressed data (> 0)
} __attribute__((packed)) sszl_header_t;

typedef struct sszl {
    uint compressed_size;   // size of compressed data   (> 0)
    uint uncompressed_size; // size of uncompressed data (> 0)
    u8 *compressed_data;    // compressed data           (!= NULL)
    u8 *uncompressed_data;  // uncompressed data         (!= NULL)
} sszl_t;

// frees a sszl and its elements
// returns void
void sszl_free(sszl_t *sp) {
    if(sp != NULL) {
        if(sp->compressed_data != NULL) {
            free(sp->compressed_data);
        }
        if(sp->uncompressed_data != NULL) {
            free(sp->uncompressed_data);
        }

        free(sp);
    }
}

// initializes a sszl
// returns non-NULL sszl_t* on success; NULL on failure
sszl_t *sszl_init(void) {
    sszl_t *sp = NULL;
    sp = malloc(sizeof(sszl_t));
    if(sp == NULL) {
        ERROR_ALLOC("sszl");
        return NULL;
    }
    *sp = (sszl_t){0, 0, NULL, NULL};

    sp->compressed_data = malloc(0);
    if(sp->compressed_data == NULL) {
        ERROR_ALLOC("sszl->compressed data");
        goto error;
    }

    sp->uncompressed_data = malloc(0);
    if(sp->uncompressed_data == NULL) {
        ERROR_ALLOC("sszl->uncompressed data");
        goto error;
    }

    return sp;
error:
    if(sp != NULL) {
        sszl_free(sp);
    }

    return NULL;
}

// reads an sszl from a data pointer
// returns non-NULL sszl_t* on success; NULL on failure
sszl_t *sszl_read(const u8 *data, uint size) {
    if(data == NULL) {
        ERROR_BAD("data");
        return NULL;
    }

    if(size < 1) {
        ERROR_BAD("size");
        return NULL;
    }

    sszl_t *sp = sszl_init();
    if(sp == NULL) {
        ERROR("could not init sszl");
        return NULL;
    }

    stream_t *stp = stream_init();
    if(stp == NULL) {
        ERROR("could not init stream");
        goto error;
    }

    if(stream_set(stp, data, size) == 1) {
        ERROR("could not set stream");
        goto error;
    }

    sszl_header_t sh = (sszl_header_t){{0}, 0, 0, 0};
    stream_read(stp, &sh, sizeof(sszl_header_t));

    if(memcmp(sh.magic, "SSZL", 4)) {
        ERROR("not a sszl");
        goto error;
    }

    sp->compressed_size = sh.compressed_size;
    sp->uncompressed_size = sh.uncompressed_size;

    sp->compressed_data = realloc(sp->compressed_data, sp->compressed_size);
    if(sp->compressed_data == NULL) {
        ERROR_REALLOC("sszl->compressed data");
        goto error;
    }

    sp->uncompressed_data = realloc(sp->uncompressed_data, sp->uncompressed_size);
    if(sp->uncompressed_data == NULL) {
        ERROR_REALLOC("sszl->uncompressed data");
        goto error;
    }

    stream_read(stp, sp->compressed_data, sp->compressed_size);

    return sp;
error:
    if(sp != NULL) {
        sszl_free(sp);
    }

    return NULL;
}

// read sszl from stream
// returns non-NULL sszl_t* on success; NULL on failure
sszl_t *sszl_read_stream(stream_t *stp) {
    if(stp == NULL) {
        ERROR_BAD("stream");
        return NULL;
    }

    return sszl_read(stp->ptr, stp->size);
}

// read sszl from file
// returns non-NULL sszl_t* on success; NULL on failure
sszl_t *sszl_read_file(const char *filename) {
    if(filename == NULL) {
        ERROR_BAD("filename");
        return NULL;
    }

    stream_t *stp = stream_read_file(filename);
    if(stp == NULL) {
        ERROR("could not init stream");
        return NULL;
    }

    return sszl_read_stream(stp);
}

#endif
