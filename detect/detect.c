#include <fcntl.h>
#include <kvm.h>
#include <limits.h>
#include <nlist.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/sysent.h>


int detectRootKit(char *syscall_name, char *syscallIndex){
    char errbuf[_POSIX2_LINE_MAX];
    kvm_t *kd;
    struct nlist nl[] = { {NULL}, {NULL}, {NULL}, };

    unsigned long addr;
    int callnum;
    struct sysent call;

    nl[0].n_name = "sysent";
    nl[1].n_name = syscall_name;
    callnum = (int)strtol(syscallIndex, (char **)NULL, 10);

    printf("\nCheck system call %d: %s\n\n", syscallIndex, syscall_name);

    kd = kvm_openfiles(NULL, NULL, NULL, O_RDWR, errbuf);
    if(!kd) {
        fprintf(stderr, "ERROR: %s\n", errbuf);
        return 2;
    }

    if(kvm_nlist(kd, nl) < 0){
        fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
        return 2;
    }

    if(nl[0].n_value){
        printf("%s[] is 0x%x at 0x%lx\n", nl[0].n_name, nl[0].n_type, nl[0].n_value);
    } else {
        fprintf(stderr, "ERROR: %s not found (GG ez FAIL)\n", nl[0].n_name);
        return 2;
    }

    if(!nl[1].n_value){
        fprintf(stderr, "ERROR: %s not found\n", nl[1].n_name);
        return 2;
    }

    addr = nl[0].n_value + callnum * sizeof(struct sysent);

    if(kvm_read(kd, addr, &call, sizeof(struct sysent)) < 0){
        fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
        return 2;
    }

    printf("sysent[%d] is at 0x%lx and its sy_call member points to " "%p\n", callnum, addr, call.sy_call);

    //check if correct
    if ((uintptr_t)call.sy_call != nl[1].n_value) {
        printf("Alert! It should point to 0x%lx instead\n", nl[1].n_value);
        return 1;
    }

    if(kvm_close(kd) < 0) {
        fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
        return 2;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    int flagHooked = 1;
    //check if read has been hooked
    if(detectRootKit("sys_read", "3") == 1){
        printf("Rootkit detected! Syscall read has been hooked\n");
        flagHooked = 0;
    }

    //check if write has been hooked
    if(detectRootKit("sys_mkdir", "136") == 1){
        printf("Rootkit detected! Syscall mkdir has been hooked\n");
        flagHooked = 0;
    }

    //check if write has been hooked
    if(detectRootKit("sys_write", "4") == 1){
        printf("Rootkit detected! Syscall write has been hooked\n");
        flagHooked = 0;
    }

    //check if open has been hooked
    if(detectRootKit("sys_open", "5") == 1) {
        printf("Rootkit detected! Syscall open has been hooked\n");
        flagHooked = 0;
    }

    //check to see if readv has been hooked
    if(detectRootKit("sys_readv", "120") == 1){
        printf("Rootkit detected! Syscall readv has been hooked\n");
        flagHooked = 0;
    }

    if(flagHooked == 1){
        printf("\n\nprobably no rootkit\n");
    }

}

