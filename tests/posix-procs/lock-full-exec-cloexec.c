// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
/* Each old-image public close waits for its own persisted observer ACK. */
#include "lock-full-exec-io.h"
extern int full_exec_binding(uint64_t[9]);
extern int full_exec_sample(unsigned,uint64_t[4]);
extern int full_exec_old_scope(unsigned,uint64_t,uint64_t,uint64_t,uint64_t);
extern int full_cloexec_arm(const uint64_t *);
extern int full_cloexec_snapshot(unsigned,uint64_t[24]);
extern int full_cloexec_valid(const uint64_t *,const uint64_t *,unsigned,unsigned,uint64_t);
extern int full_cloexec_pending(uint64_t,uint64_t,uint64_t);
extern int full_cloexec_receipts_same(const uint64_t *,const uint64_t *);
extern int full_row_valid(const uint64_t[20][6]);
static int exec_alias=-1;
static uint64_t exec_a_source[2],exec_b_source[2];
static unsigned exec_closed;
enum { EXEC_WORDS=352, EXEC_BYTES=2816 };
_Static_assert(sizeof(exec_state)==4096,"one static state page");
static uint64_t exec_tag(unsigned phase) {return exec_nonce^(uint64_t)phase;}
static unsigned exec_count(void) {return FULL_EXEC==5 ? 2u : 1u;}
static unsigned exec_slot(unsigned ordinal) {return 32u+(ordinal-1u)*160u;}
static int exec_read(void) {return full_exec_io_read(exec_state_fd,exec_state,0,EXEC_WORDS);}
static int exec_write(unsigned at,unsigned words) {return full_exec_io_write(exec_state_fd,exec_state+at,at,words);}
static int exec_wait(unsigned word,uint64_t wanted,uint64_t previous) {
    for (unsigned n=0;n<3000;++n) {
        uint64_t marker;
        if (full_exec_io_read(exec_state_fd,&marker,word,1)) return -1;
        int phase=full_cloexec_pending(marker,wanted,previous);
        if (!phase) return 0;
        if (phase<0) return -1;
        nanosleep(&tick,NULL);
    }
    return -1;
}
static void exec_freeze(void) {
    memcpy(exec_frozen,exec_state,32*8);
    for (unsigned n=1;n<=exec_count();++n)
        memcpy(exec_frozen+32+(n-1)*24,exec_state+exec_slot(n),24*8);
}
static int exec_setup(int fd,struct record *r) {
    struct stat a,state;
    uint64_t source[2],sample[4];
    exec_primary=fd;exec_alias=dup(fd);exec_state_fd=open("/tmp/lock-full-exec-state",O_RDWR);
    if (exec_alias<0 || exec_state_fd<0 || fcntl(fd,F_GETFD) || fcntl(exec_alias,F_GETFD)
        || fcntl(exec_state_fd,F_GETFD) || full_source((unsigned)exec_alias,source)
        || memcmp(source,r->source,sizeof(source)) || full_exec_binding(exec_state+8)
        || full_exec_sample((unsigned)fd,sample) || fstat(fd,&a) || fstat(exec_state_fd,&state)
        || (uint64_t)a.st_ino!=r->inode || a.st_ino==state.st_ino || state.st_size!=4096
        || exec_state[9]!=r->pid || exec_state[13]!=r->root || exec_state[14]!=r->generation
        || fcntl(exec_alias,F_SETFD,FD_CLOEXEC) || (FULL_EXEC==5 && fcntl(fd,F_SETFD,FD_CLOEXEC))) return -1;
    exec_nonce=cookie^(r->pid<<16)^(exec_state[11]<<32)^((uint64_t)FULL_EXEC<<8)^profile;
    exec_state[0]=UINT64_C(0x6578656332353602);exec_state[1]=2;exec_state[2]=FULL_EXEC;
    exec_state[3]=exec_nonce;exec_state[5]=(uint64_t)exec_state_fd;exec_state[6]=FULL_EXEC==5;
    exec_state[7]=r->inode;memcpy(exec_state+17,sample,sizeof(sample));
    exec_state[26]=256;exec_state[27]=128;exec_state[28]=8;exec_state[31]=exec_tag(1);
    for (unsigned n=1;n<=exec_count();++n) {
        int target=exec_alias;
        if (FULL_EXEC==5) target=n==1 ? (fd<exec_alias ? fd:exec_alias):(fd<exec_alias ? exec_alias:fd);
        uint64_t *receipt=exec_state+exec_slot(n);
        if (full_exec_sample((unsigned)target,receipt) || fcntl(target,F_GETFD)!=FD_CLOEXEC) return -1;
        memcpy(receipt+10,exec_state+8,9*8);receipt[19]=FD_CLOEXEC;receipt[20]=r->inode;
        receipt[21]=exec_nonce;receipt[22]=n;
    }
    exec_freeze();
    return full_cloexec_valid(exec_state,exec_frozen,1,0,profile)
        || exec_write(0,31) || exec_write(32,320) || exec_write(31,1);
}
static int exec_hold(int fd,unsigned index,struct record *r) {
    (void)r;
    if (exec_wait(30,exec_tag(2),0) || exec_read()) return fail("CLOEXEC old permission",index);
    exec_freeze();
    uint64_t sample[4];
    if (full_cloexec_valid(exec_state,exec_frozen,5,0,profile)
        || full_exec_sample((unsigned)fd,sample) || memcmp(sample,exec_state+17,sizeof(sample))
        || fcntl(fd,F_GETFD)!=(FULL_EXEC==5 ? FD_CLOEXEC:0)
        || fcntl(exec_alias,F_GETFD)!=FD_CLOEXEC || fcntl(exec_state_fd,F_GETFD)
        || full_cloexec_arm(exec_state)) return fail("CLOEXEC exact armed descriptors",index);
    char p[2]={(char)('0'+profile),0}, state[12];
    snprintf(state,sizeof(state),"%d",exec_state_fd);
    char *args[]={"procs-child","full-after-exec",p,"0",state,NULL}; char *env[]={NULL};
    execve("/bin/procs-child",args,env);return fail("CLOEXEC real exec returned",index);
}
int full_cloexec_public(unsigned fd) {
    unsigned n=++exec_closed;
    if (n>exec_count()) return -1;
    unsigned at=exec_slot(n);
    if (exec_state[at]!=(uint64_t)fd || full_cloexec_snapshot(fd,exec_state+at)) return -1;
    exec_state[at+9]=1;exec_state[at+23]=exec_tag(16+n);
    if (full_cloexec_valid(exec_state,exec_frozen,2,n,profile)
        || exec_write(at,23) || exec_write(at+23,1)
        || exec_wait(at+153,exec_tag(32+n),0) || exec_read()
        || full_cloexec_valid(exec_state,exec_frozen,3,n,profile)) return -1;
    return 0;
}
static int exec_before(int controller,int witness,const struct record records[20]) {
    uint64_t who[4];struct stat a,b;
    exec_state_fd=open("/tmp/lock-full-exec-state",O_RDWR);
    if (exec_state_fd<0 || exec_read()) return fail("CLOEXEC observer INITIAL",0);
    exec_nonce=cookie^(records[0].pid<<16)^(exec_state[11]<<32)^((uint64_t)FULL_EXEC<<8)^profile;
    exec_freeze();
    if (full_cloexec_valid(exec_state,exec_frozen,1,0,profile) || exec_state[3]!=exec_nonce
        || exec_state[9]!=records[0].pid || exec_state[13]!=records[0].root || exec_state[14]!=records[0].generation
        || exec_state[7]!=records[0].inode || exec_state[19]!=records[0].source[0] || exec_state[20]!=records[0].source[1]
        || full_source((unsigned)controller,exec_state+21) || full_identity((unsigned)getpid(),who)
        || who[0]==records[0].pid || who[2]!=records[0].root || who[3]!=records[0].generation
        || full_source((unsigned)witness,exec_a_source) || full_source((unsigned)exec_foreign_b,exec_b_source)
        || fstat(witness,&a) || fstat(exec_foreign_b,&b) || (uint64_t)a.st_ino!=records[0].inode
        || (uint64_t)b.st_ino!=records[1].inode || a.st_ino==b.st_ino
        || !memcmp(exec_a_source,records[0].source,sizeof(exec_a_source))
        || !memcmp(exec_b_source,records[1].source,sizeof(exec_b_source))) return fail("CLOEXEC foreign frozen identity",0);
    exec_state[23]=who[0];exec_state[24]=who[2];exec_state[25]=who[3];exec_freeze();return 0;
}
static int exec_budget(int controller,uint64_t epoch,unsigned published,unsigned common) {
    uint64_t out[6]={0};
    for (unsigned n=0;n<1024;++n) {
        if (totals(controller,epoch,out)) return -1;
        if (!out[2] && !out[3]) break;
    }
    return out[1]!=published || out[2] || out[3] || out[4]!=common || out[5]!=8;
}
static int exec_foreign(int controller,uint64_t epoch,int witness,const struct record records[20],int removed) {
    struct stat st;uint64_t source[2];
    if (full_source((unsigned)witness,source) || memcmp(source,exec_a_source,sizeof(source))
        || fstat(witness,&st) || (uint64_t)st.st_ino!=records[0].inode
        || full_source((unsigned)exec_foreign_b,source) || memcmp(source,exec_b_source,sizeof(source))
        || fstat(exec_foreign_b,&st) || (uint64_t)st.st_ino!=records[1].inode) return -1;
    for (unsigned file=0;file<2;++file) for (unsigned edge=0;edge<2;++edge) {
        int target=file ? exec_foreign_b:witness;
        struct flock lock={.l_type=F_WRLCK,.l_whence=SEEK_SET,.l_start=(off_t)(edge ? 2*(records[file].count-1):0),.l_len=1};
        if (fcntl(target,F_GETLK,&lock)) return -1;
        if (!file && removed) {if (lock.l_type!=F_UNLCK) return -1;}
        else if (lock.l_type!=F_WRLCK || lock.l_pid!=(!file && FULL_EXEC>=4 ? -1:(pid_t)records[file].pid)
            || lock.l_start!=(off_t)(edge ? 2*(records[file].count-1):0) || lock.l_len!=1) return -1;
        lock.l_type=F_WRLCK;errno=0;
        int result=fcntl(target,F_SETLK,&lock);
        if (!file && removed) {
            if (result || exec_budget(controller,epoch,245,117)) return -1;
            lock.l_type=F_UNLCK;if (fcntl(target,F_SETLK,&lock) || exec_budget(controller,epoch,244,116)) return -1;
        } else if (result!=-1 || errno!=EAGAIN) return -1;
    }
    return 0;
}
static int exec_capture_row(int controller,uint64_t epoch,unsigned n) {
    unsigned at=exec_slot(n),present=FULL_EXEC==3 || (FULL_EXEC==5 && n==2);
    uint64_t *c=exec_state+at+144;
    for (unsigned page=0;page<20;++page) {
        uint64_t *out=exec_state+at+24+page*6;
        int result=full_telemetry((unsigned)controller,1,cookie,epoch,(28u<<16)|page,out);
        if ((present && result) || (!present && result!=-304)) return -1;
        if (!present) memset(out,0,6*8);
    }
    c[2]=present;c[3]=present ? 20:UINT64_C(0xfffff)<<32;c[4]=present;c[5]=present;
    return present ? full_row_valid((const uint64_t (*)[6])(exec_state+at+24)):0;
}
static int exec_capture(int controller,int witness,uint64_t epoch,const struct record records[20]) {
    uint64_t out[6];
    /* Only the observer owns row/control storage, including absent page payloads. */
    exec_state[4]=epoch;exec_frozen[4]=epoch;exec_state[29]=2;exec_state[30]=exec_tag(2);
    for (unsigned n=1;n<=20;++n) {
        if (full_telemetry((unsigned)controller,1,cookie,epoch,(28u<<16)|(n-1),out)!=-304) return fail("CLOEXEC initial exact absence",n);
    }
    if (exec_foreign(controller,epoch,witness,records,0) || exec_write(4,1) || exec_write(21,9) || exec_write(30,1)) return fail("CLOEXEC permission commit",0);
    for (unsigned n=1;n<=exec_count();++n) {
        unsigned at=exec_slot(n);uint64_t *c=exec_state+at+144;
        if (exec_wait(at+23,exec_tag(16+n),0) || exec_read()
            || full_cloexec_valid(exec_state,exec_frozen,2,n,profile)) return fail("CLOEXEC exact public Ok receipt",n);
        memcpy(exec_closed_receipts+(n-1)*24,exec_state+at,24*8);
        if (n==exec_count()) {
            if (full_telemetry((unsigned)controller,2,cookie,epoch,0,out)) return fail("CLOEXEC old Stop",n);
        } else if (full_telemetry((unsigned)controller,3,cookie,epoch,0,out)) return fail("CLOEXEC still-active Header",n);
        memcpy(c+10,out,sizeof(out));
        c[0]=n;c[1]=exec_nonce;c[6]=1;c[7]=n;c[8]=exec_nonce;c[9]=exec_tag(32+n);
        if (exec_capture_row(controller,epoch,n) || full_cloexec_valid(exec_state,exec_frozen,3,n,profile)
            || exec_budget(controller,epoch,FULL_EXEC==4 || n<exec_count() ? 256u:244u,FULL_EXEC==4 || n<exec_count() ? 128u:116u)
            || (n==exec_count() && exec_foreign(controller,epoch,witness,records,FULL_EXEC!=4))
            || exec_write(at+24,129) || exec_write(at+154,6) || exec_write(at+153,1)) return fail("CLOEXEC persisted exact row and ACK",n);
    }
    if (exec_wait(31,exec_tag(48),exec_tag(1)) || exec_read()
        || full_cloexec_valid(exec_state,exec_frozen,4,0,profile)
        || full_cloexec_receipts_same(exec_state,exec_closed_receipts)) return fail("CLOEXEC fresh authenticated image and immutable receipts",0);
    for (unsigned n=1;n<=exec_count();++n) {
        unsigned at=exec_slot(n),present=FULL_EXEC==3 || (FULL_EXEC==5 && n==2);
        if (present) for (unsigned page=0;page<20;++page) {
            if (full_telemetry((unsigned)controller,1,cookie,epoch,(28u<<16)|page,out)
                || memcmp(out,exec_state+at+24+page*6,sizeof(out))) return fail("CLOEXEC unchanged stopped row",page);
        }
    }
    if (exec_budget(controller,epoch,256,128) || census(controller,records,epoch)) return fail("CLOEXEC real full refill witness",0);
    exec_state[30]=exec_tag(49);
    if (exec_write(30,1)) return fail("CLOEXEC FINAL_ACK commit",0);
    printf("lock-full: exec cloexec profile=%u mode=%u closes=%u replay=confirmed discard=once oldscope=denied published=256 common=128 payers=8\n",profile,FULL_EXEC,exec_count());
    return 0;
}
static int exec_after(int state_fd) {
    exec_state_fd=state_fd;
    if (exec_read()) return fail("CLOEXEC new complete old state",0);
    exec_nonce=cookie^(exec_state[43]<<16)^(exec_state[45]<<32)^((uint64_t)FULL_EXEC<<8)^profile;
    if (exec_state[3]!=exec_nonce || exec_state[2]!=FULL_EXEC || exec_state[5]!=(uint64_t)state_fd) return fail("CLOEXEC exact new state case and nonce",0);
    exec_freeze();
    for (unsigned n=1;n<=exec_count();++n)
        if (full_cloexec_valid(exec_state,exec_frozen,3,n,profile)) return fail("CLOEXEC old stopped proof after CRT",n);
    exec_primary=(int)exec_state[17];
    int old_alias=(int)exec_state[32];
    if (FULL_EXEC==5) old_alias=(int)(exec_state[32]==exec_state[17] ? exec_state[192]:exec_state[32]);
    errno=0;if (fcntl(old_alias,F_GETFD)!=-1 || errno!=EBADF) return fail("CLOEXEC U absent after CRT",0);
    uint64_t sample[4],who[9],denied[6];struct stat st;
    int resident=FULL_EXEC==5 ? state_fd:exec_primary;
    if (fcntl(state_fd,F_GETFD) || fstat(state_fd,&st) || st.st_size!=4096 || (uint64_t)st.st_ino==exec_state[7]
        || full_exec_binding(who) || full_exec_sample((unsigned)resident,sample)
        || full_exec_old_scope((unsigned)resident,exec_state[21],exec_state[22],cookie,exec_state[4])!=-310
        || full_telemetry((unsigned)resident,3,cookie,exec_state[4],0,denied)!=-310) return fail("CLOEXEC new authority old Scope denied",0);
    if (FULL_EXEC==5) {
        errno=0;if (fcntl(exec_primary,F_GETFD)!=-1 || errno!=EBADF) return fail("CLOEXEC T absent after CRT",0);
    } else if (sample[0]!=exec_state[17] || sample[2]!=exec_state[19] || sample[3]!=exec_state[20]
        || fcntl(exec_primary,F_GETFD) || fstat(exec_primary,&st) || (uint64_t)st.st_ino!=exec_state[7]) return fail("CLOEXEC exact retained T",0);
    if (FULL_EXEC==5) {
        exec_primary=open("/tmp/lock-full-file-0",O_RDWR);
        uint64_t source[2];
        if (exec_primary<0 || full_source((unsigned)exec_primary,source)
            || (source[0]==exec_state[19] && source[1]==exec_state[20]) || fstat(exec_primary,&st)
            || (uint64_t)st.st_ino!=exec_state[7]) return fail("CLOEXEC fresh refill Da",0);
    }
    if (FULL_EXEC!=4) for (unsigned n=0;n<segments(0,0);++n)
        if (set(exec_primary,F_WRLCK,n)) return fail("CLOEXEC actual twelve-segment refill",n);
    memcpy(exec_state+8,who,sizeof(who));exec_state[29]=sample[1];exec_state[31]=exec_tag(48);
    if (full_cloexec_valid(exec_state,exec_frozen,4,0,profile) || exec_write(8,9)
        || exec_write(29,1) || exec_write(31,1) || exec_wait(30,exec_tag(49),exec_tag(2))) return fail("CLOEXEC new verified FINAL_ACK",0);
    for (unsigned n=0;n<segments(0,0);++n)
        if (set(exec_primary,F_UNLCK,n)) return fail("CLOEXEC final teardown",n);
    return close(exec_primary) || close(state_fd) ? fail("CLOEXEC close after FINAL_ACK",0):0;
}
