/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
extern void wait_fifo_hooks_begin(void), wait_fifo_hooks_end(void);
extern int wait_fifo_arm(int fd, unsigned holder, unsigned long long nonce);
extern int wait_fifo_selected(unsigned long long nonce, unsigned index);
static _Thread_local unsigned fifo_index;
static int fifo_ready[2];
unsigned wait_fifo_index(void) { return fifo_index; }
void wait_fifo_ready(unsigned index) { if (index>=1 && index<=2) __atomic_store_n(&fifo_ready[index-1],1,__ATOMIC_RELEASE); }
struct fifo_worker {unsigned index;int fd;short kind;long long start,length;int result,error;size_t peak;};
static void *fifo_worker(void *pointer) {
    struct fifo_worker *worker=pointer;fifo_index=worker->index;
    pthread_attr_t attr;void *base=NULL;size_t size=0;
    if (pthread_getattr_np(pthread_self(),&attr) || pthread_attr_getstack(&attr,&base,&size) || pthread_attr_destroy(&attr) || size!=PTHREAD_STACK_MIN) {worker->result=778;return NULL;}
    uintptr_t here;__asm__ volatile("mov %0, sp":"=r"(here));uintptr_t painted=here-512,top=(uintptr_t)base+size;
    if (painted<(uintptr_t)base || here>top) {worker->result=779;return NULL;}
    for (uintptr_t p=(uintptr_t)base;p<painted;p++) *(volatile unsigned char *)p=0xa7;
    struct flock lock={.l_type=worker->kind,.l_whence=SEEK_SET,.l_start=worker->start,.l_len=worker->length};
    errno=0;worker->result=fcntl(worker->fd,38,&lock);worker->error=errno;
    uintptr_t first=(uintptr_t)base;while(first<painted && *(volatile unsigned char *)first==0xa7)first++;
    worker->peak=top-first;return NULL;
}
static int fifo_stage(unsigned index) {
    struct timespec tick={0,1000000};
    for(unsigned n=0;n<10000;n++){if(__atomic_load_n(&fifo_ready[index-1],__ATOMIC_ACQUIRE))return 1;nanosleep(&tick,NULL);}return 0;
}
static void public_wait_fifo(void) {
    int fd=open("/tmp/public-wait-fifo",O_CREAT|O_RDWR,0666);expect("open FIFO source",fd>=0,1);if(fd<0)return;
    int commands[2],replies[2];if(pipe(commands)||pipe(replies)){expect("FIFO pipes",0,1);close(fd);return;}
    pid_t holder=fork();expect("fork FIFO holder",holder>=0,1);
    if(holder==0){close(commands[1]);close(replies[0]);char command;
        while(read(commands[0],&command,1)==1){if(command=='Q')_exit(0);
            struct flock lock={.l_type=command=='L'?F_RDLCK:F_UNLCK,.l_whence=SEEK_SET,.l_start=command=='U'?4:0,.l_len=command=='U'?4:8};
            if(command=='L'){lock.l_len=4;if(fcntl(fd,F_SETLK,&lock))_exit(93);lock.l_type=F_WRLCK;lock.l_start=4;}
            if(fcntl(fd,F_SETLK,&lock)||write(replies[1],&command,1)!=1)_exit(94);
        }_exit(95);
    }
    close(commands[0]);close(replies[1]);if(holder<0){close(commands[1]);close(replies[0]);close(fd);return;}
    pthread_attr_t attributes;expect("FIFO attrs",pthread_attr_init(&attributes),0);expect("FIFO actual64K allocation",pthread_attr_setstacksize(&attributes,PTHREAD_STACK_MIN),0);
    for(unsigned mode=1;mode<=2;mode++){
        expect("FIFO child adjacent Read/Write blockers",wait_holder_exchange(commands[1],replies[0],'L'),1);
        struct fifo_worker workers[2]={{.index=1,.fd=-1,.kind=mode==1?F_RDLCK:F_WRLCK,.start=0,.length=8,.result=777},{.index=2,.fd=-1,.kind=F_RDLCK,.start=4,.length=4,.result=777}};
        pthread_t threads[2];unsigned created=0;
        __atomic_store_n(&fifo_ready[0],0,__ATOMIC_RELEASE);__atomic_store_n(&fifo_ready[1],0,__ATOMIC_RELEASE);wait_fifo_hooks_begin();
        for(unsigned index=0;index<2;index++){
            workers[index].fd=open("/tmp/public-wait-fifo",O_RDWR);expect("open distinct FIFO OFD",workers[index].fd>=0,1);if(workers[index].fd<0)break;
            int error=pthread_create(&threads[index],&attributes,fifo_worker,&workers[index]);expect("FIFO worker create",error,0);if(error)break;created++;
            expect("FIFO accepted Sleeping in registration order",fifo_stage(index+1),1);
        }
        unsigned long long nonce=(1ULL<<32)|mode;
        if(created==2){
            int armed=wait_fifo_arm(fd,(unsigned)holder,nonce);expect("arm authenticated finite FIFO gate",armed,0);
            expect("single child unlock opens only right range",wait_holder_exchange(commands[1],replies[0],'U'),1);
            struct flock set={.l_type=F_WRLCK,.l_whence=SEEK_SET,.l_start=4,.l_len=4};errno=0;int result=fcntl(fd,F_SETLK,&set),error=errno;
            expect("later real SET conflicts with selected WAIT",result,-1);expect("later SET genuine EAGAIN",error,EAGAIN);
            expect("real Selector chooses exact oldest eligible key",wait_fifo_selected(nonce,mode==1?1:2),0);
            struct flock get={.l_type=F_WRLCK,.l_whence=SEEK_SET,.l_start=4,.l_len=4};expect("query granted OFD blocker",fcntl(fd,F_GETLK,&get),0);expect("selected WAIT owns actual Read blocker",get.l_type,F_RDLCK);expect("selected blocker is OFD",get.l_pid,-1);
            /* Also permits a bypass mutant's newly granted PID lock to be cleaned. */
            set.l_type=F_UNLCK;expect("clean late PID SET if mutant granted",fcntl(fd,F_SETLK,&set),0);
        } else expect("unlock incomplete FIFO setup",wait_holder_exchange(commands[1],replies[0],'U'),1);
        if(mode==2 && created>0){expect("close older still-blocked Write WAIT",close(workers[0].fd),0);workers[0].fd=-1;}
        for(unsigned index=0;index<created;index++){
            expect("FIFO worker join",pthread_join(threads[index],NULL),0);
            expect("FIFO canonical worker outcome",workers[index].result,mode==2&&index==0?-1:0);
            if(mode==2&&index==0)expect("old blocked WAIT close errno",workers[index].error,EBADF);
            expect("FIFO painted path<=16K",workers[index].peak>0&&workers[index].peak<=16384,1);
            printf("posix-procs: FIFO case %u worker %u stack %zu bytes\n",mode,index+1,workers[index].peak);
        }
        for(unsigned index=0;index<2;index++)if(workers[index].fd>=0)expect("close FIFO worker OFD",close(workers[index].fd),0);
        wait_fifo_hooks_end();expect("clear child FIFO locks",wait_holder_exchange(commands[1],replies[0],'C'),1);
    }
    expect("destroy FIFO attrs",pthread_attr_destroy(&attributes),0);char quit='Q';expect("stop FIFO holder",write(commands[1],&quit,1),1);close(commands[1]);close(replies[0]);reap(holder,0);close(fd);
    if(!failures)printf("posix-procs: genuine FIFO oldest eligible Read, blocked older Write and later PID SET ok\n");
}
