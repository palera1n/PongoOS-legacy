#undef panic
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <mach/mach.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <libkern/OSCacheControl.h>
#include <TargetConditionals.h>
#if TARGET_OS_OSX
#   include <pthread.h>
#endif

#define SWAP32(x) (((x & 0xff000000) >> 24) | ((x & 0xff0000) >> 8) | ((x & 0xff00) << 8) | ((x & 0xff) << 24))

#define MACH_MAGIC   MH_MAGIC_64
#define MACH_SEGMENT LC_SEGMENT_64
typedef struct fat_header         fat_hdr_t;
typedef struct fat_arch           fat_arch_t;
typedef struct mach_header_64     mach_hdr_t;
typedef struct load_command       mach_lc_t;
typedef struct segment_command_64 mach_seg_t;
typedef struct thread_command     mach_th_t;

typedef struct boot_args
{
    uint16_t Revision;
    uint16_t Version;
    uint32_t __pad0;
    uint64_t virtBase;
    uint64_t physBase;
    uint64_t memSize;
    uint64_t topOfKernelData;
    uint64_t Video[6];
    uint32_t machineType;
    uint32_t __pad1;
    void    *deviceTreeP;
    uint32_t deviceTreeLength;
    union
    {
        struct
        {
            char     CommandLine[0x100];
            uint32_t __pad;
            uint64_t bootFlags;
            uint64_t memSizeActual;
        } iOS12;
        struct
        {
            char     CommandLine[0x260];
            uint32_t __pad;
            uint64_t bootFlags;
            uint64_t memSizeActual;
        } iOS13;
    };
} __attribute__((packed)) boot_args;

extern kern_return_t mach_vm_protect(vm_map_t task, mach_vm_address_t addr, mach_vm_size_t size, boolean_t set_max, vm_prot_t prot);

extern void module_entry(void);
extern void (*preboot_hook)(void);
void *ramdisk_buf = NULL;
uint32_t ramdisk_size = 0;
void *gEntryPoint;
boot_args *gBootArgs;

static boot_args BootArgs;
#define NUM_JIT 1
static struct {
    void *addr;
    size_t size;
} jits[NUM_JIT];

uint64_t get_ticks(void)
{
    return __builtin_arm_rsr64("cntpct_el0");
}

void command_register(const char* name, const char* desc, void (*cb)(const char* cmd, char* args))
{
    // nop
}

void invalidate_icache(void)
{
    // Kinda jank, but we know we're only gonna clean the JIT areas...
    for(uint32_t i = 0; i < NUM_JIT; ++i)
    {
        if(jits[i].addr)
        {
            sys_icache_invalidate(jits[i].addr, jits[i].size);
        }
    }
}

#if !TARGET_OS_OSX
void pthread_jit_write_protect_np(int exec)
{
    for(uint32_t i = 0; i < NUM_JIT; ++i)
    {
        if(jits[i].addr)
        {
            kern_return_t ret = mach_vm_protect(mach_task_self(), (mach_vm_address_t)jits[i].addr, jits[i].size, 0, VM_PROT_READ | (exec ? VM_PROT_EXECUTE : VM_PROT_WRITE));
            if(ret != KERN_SUCCESS)
            {
                fprintf(stderr, "mach_vm_protect(JIT): %s\n", mach_error_string(ret));
                exit(-1);
            }
        }
    }
}
#endif

void* jit_alloc(size_t count, size_t size)
{
    // overflow, but not my problem
    size_t len = count * size;
    if(!len)
    {
        fprintf(stderr, "jit_alloc: bad size\n");
        exit(-1);
    }

    int prot  = PROT_READ | PROT_WRITE;
    int flags = MAP_ANON | MAP_PRIVATE;
#if TARGET_OS_OSX
    prot  |= PROT_EXEC;
    flags |= MAP_JIT;
#endif
    void *mem = mmap(NULL, len, prot, flags, -1, 0);
    if(mem == MAP_FAILED)
    {
        fprintf(stderr, "mmap(JIT): %s\n", strerror(errno));
        exit(-1);
    }

    pthread_jit_write_protect_np(0);

    bzero(mem, len);

    for(uint32_t i = 0; i < NUM_JIT; ++i)
    {
        if(!jits[i].addr)
        {
            jits[i].addr = mem;
            jits[i].size = len;
            return mem;
        }
    }
    fprintf(stderr, "jit_alloc: no space in jit array\n");
    exit(-1);
}

void jit_free(void *mem)
{
    for(uint32_t i = 0; i < NUM_JIT; ++i)
    {
        if(jits[i].addr == mem)
        {
            munmap(mem, jits[i].size);
            jits[i].addr = 0;
            jits[i].size = 0;
            return;
        }
    }
    fprintf(stderr, "jit_free: bad addr: %p\n", mem);
    exit(-1);
}
void realpanic(const char *str, ...)
{
    char *ptr = NULL;
    va_list va;

    va_start(va, str);
    vasprintf(&ptr, str, va);
    va_end(va);

    panic(ptr);
}
int main(int argc, char *argv[])
{
    if(argc < 3)
    {
        fprintf(stderr, "usage: %s <kernel> <output>\n", argv[0]);
        return -1;
    }
    int fd = open(argv[1], O_RDONLY);
    if(fd < 0)
    {
        fprintf(stderr, "open: %s: %s\n", argv[1], strerror(errno));
        return -1;
    }
    struct stat s;
    if(fstat(fd, &s) != 0)
    {
        fprintf(stderr, "fstat: %s\n", strerror(errno));
        exit(-1);
    }
    size_t flen = s.st_size;
    if(flen < sizeof(mach_hdr_t))
    {
        fprintf(stderr, "File too short for header.\n");
        exit(-1);
    }
    void *file = mmap(NULL, flen, PROT_READ, MAP_FILE | MAP_PRIVATE, fd, 0);
    if(file == MAP_FAILED)
    {
        fprintf(stderr, "mmap(file): %s\n", strerror(errno));
        exit(-1);
    }

    fat_hdr_t *fat = file;
    if(fat->magic == FAT_CIGAM)
    {
        bool found = false;
        fat_arch_t *arch = (fat_arch_t*)(fat + 1);
        for(size_t i = 0; i < SWAP32(fat->nfat_arch); ++i)
        {
            if(SWAP32(arch[i].cputype) == CPU_TYPE_ARM64)
            {
                uint32_t offset = SWAP32(arch[i].offset);
                uint32_t newsize = SWAP32(arch[i].size);
                if(offset > flen || newsize > flen - offset)
                {
                    fprintf(stderr, "Fat arch out of bounds.\n");
                    exit(-1);
                }
                if(newsize < sizeof(mach_hdr_t))
                {
                    fprintf(stderr, "Fat arch is too short to contain a Mach-O.\n");
                    exit(-1);
                }
                file = (void*)((uintptr_t)file + offset);
                flen = newsize;
                found = true;
                break;
            }
        }
        if(!found)
        {
            fprintf(stderr, "No arm64 slice in fat binary.\n");
            exit(-1);
        }
    }

    mach_hdr_t *hdr = file;
    if(hdr->magic != MACH_MAGIC)
    {
        fprintf(stderr, "Bad magic: %08x\n", hdr->magic);
        exit(-1);
    }
    if(flen < sizeof(mach_hdr_t) + hdr->sizeofcmds)
    {
        fprintf(stderr, "File too short for load commands.\n");
        exit(-1);
    }

    uintptr_t base        = ~0,
              lowest      = ~0,
              highest     =  0,
              entry       =  0;
    for(mach_lc_t *cmd = (mach_lc_t*)(hdr + 1), *end = (mach_lc_t*)((uintptr_t)cmd + hdr->sizeofcmds); cmd < end; cmd = (mach_lc_t*)((uintptr_t)cmd + cmd->cmdsize))
    {
        if((uintptr_t)cmd + sizeof(*cmd) > (uintptr_t)end || (uintptr_t)cmd + cmd->cmdsize > (uintptr_t)end || (uintptr_t)cmd + cmd->cmdsize < (uintptr_t)cmd)
        {
            fprintf(stderr, "Bad LC: 0x%lx\n", (uintptr_t)cmd - (uintptr_t)hdr);
            exit(-1);
        }
        if(cmd->cmd == MACH_SEGMENT)
        {
            mach_seg_t *seg = (mach_seg_t*)cmd;
            size_t off = seg->fileoff + seg->filesize;
            if(off > flen || off < seg->fileoff)
            {
                fprintf(stderr, "Bad segment: 0x%lx\n", (uintptr_t)cmd - (uintptr_t)hdr);
                exit(-1);
            }
            uintptr_t start = seg->vmaddr;
            if(start < lowest)
            {
                lowest = start;
            }
            uintptr_t end = start + seg->vmsize;
            if(end > highest)
            {
                highest = end;
            }
            if(seg->fileoff == 0 && seg->filesize > 0)
            {
                base = start;
            }
        }
        else if(cmd->cmd == LC_UNIXTHREAD)
        {
            struct
            {
                uint32_t cmd;
                uint32_t cmdsize;
                uint32_t flavor;
                uint32_t count;
                _STRUCT_ARM_THREAD_STATE64 state;
            } *th = (void*)cmd;
            if(th->flavor != ARM_THREAD_STATE64)
            {
                fprintf(stderr, "Bad thread state flavor.\n");
                exit(-1);
            }
            entry = th->state.__pc;
        }
    }

    if(base == ~0 || highest < lowest || entry == 0)
    {
        fprintf(stderr, "Bad memory layout, base: 0x%lx, lowest: 0x%lx, highest: 0x%lx, entry: 0x%lx\n", base, lowest, highest, entry);
        exit(-1);
    }
    size_t mlen = highest - lowest;
    void *mem = mmap(NULL, mlen, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if(mem == MAP_FAILED)
    {
        fprintf(stderr, "mmap: %s\n", strerror(errno));
        exit(-1);
    }
    for(mach_lc_t *cmd = (mach_lc_t*)(hdr + 1), *end = (mach_lc_t*)((uintptr_t)cmd + hdr->sizeofcmds); cmd < end; cmd = (mach_lc_t*)((uintptr_t)cmd + cmd->cmdsize))
    {
        if(cmd->cmd == MACH_SEGMENT)
        {
            mach_seg_t *seg = (mach_seg_t*)cmd;
            size_t size = seg->filesize < seg->vmsize ? seg->filesize : seg->vmsize;
            memcpy((void*)((uintptr_t)mem + (seg->vmaddr - lowest)), (void*)((uintptr_t)hdr + seg->fileoff), size);
        }
    }

    BootArgs.Revision           = 0x1337;
    BootArgs.Version            = 0x1469;
    BootArgs.virtBase           = lowest;
    BootArgs.physBase           = (uint64_t)mem;
    BootArgs.memSize            = mlen;
    BootArgs.topOfKernelData    = (uint64_t)mem + mlen;
    BootArgs.machineType        = 0x1984;
    //BootArgs.memSizeActual      = mlen;
    strcpy(BootArgs.iOS12.CommandLine, "-yeet");

    gBootArgs = &BootArgs;
    gEntryPoint = (void*)((uintptr_t)mem + (entry - lowest));

    printf("Kernel at 0x%llx, entry at 0x%llx", (uint64_t)mem, (uint64_t)gEntryPoint);

    module_entry();
    preboot_hook();

    // recreate kernel and save it to disk
    FILE *f = fopen(argv[2], "wb");
    if(!f)
    {
        fprintf(stderr, "fopen: %s\n", strerror(errno));
        exit(-1);
    }
    void *newfile = malloc(flen);
    if(!newfile)
    {
        fprintf(stderr, "malloc: %s\n", strerror(errno));
        exit(-1);
    }
    memcpy(newfile, file, flen);
    hdr = newfile;
    for(mach_lc_t *cmd = (mach_lc_t*)(hdr + 1), *end = (mach_lc_t*)((uintptr_t)cmd + hdr->sizeofcmds); cmd < end; cmd = (mach_lc_t*)((uintptr_t)cmd + cmd->cmdsize))
    {
        if(cmd->cmd == MACH_SEGMENT)
        {
            mach_seg_t *seg = (mach_seg_t*)cmd;
            size_t size = seg->filesize < seg->vmsize ? seg->filesize : seg->vmsize;
            memcpy((void*)((uintptr_t)newfile + seg->fileoff), (void*)((uintptr_t)mem + (seg->vmaddr - lowest)), size);
        }
    }
    fwrite(newfile, 1, flen, f);
    fclose(f);
    free(newfile);

    exit(0);
}