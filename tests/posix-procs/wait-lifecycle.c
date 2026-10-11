/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
/* Only included by lifetime.c. No test-issued Cancel/Release or rescue close. */
extern int wait_lifecycle_arm(unsigned mode), wait_lifecycle_count(void);
extern int wait_lifecycle_recovered(void), wait_lifecycle_still_sleeping(void);
extern int wait_lifecycle_receiver_waiting(void);
extern unsigned long long wait_lifecycle_generation(void);
extern void wait_lifecycle_disarm(void);
static int lifecycle_ready, lifecycle_seen, lifecycle_fd, lifecycle_result, lifecycle_errno;
static uintptr_t lifecycle_base, lifecycle_painted, lifecycle_top;
static size_t lifecycle_peak;
void wait_lifecycle_stage(void) { __atomic_store_n(&lifecycle_ready,1,__ATOMIC_RELEASE); }
static size_t lifecycle_stack_peak(void) {
    uintptr_t first=lifecycle_base;
    while(first<lifecycle_painted && *(volatile unsigned char *)first==0xa7)first++;
    return lifecycle_top-first;
}
void wait_lifecycle_exit(void) {
    lifecycle_peak=lifecycle_stack_peak();
    pthread_exit((void *)(uintptr_t)1);
}
/* Engineering genuine-End stress. pthread_exit is not async-signal-safe. */
static void lifecycle_signal(int signal) {
    __atomic_store_n(&lifecycle_seen,signal,__ATOMIC_RELEASE);
    wait_lifecycle_exit();
}
static void *lifecycle_worker(void *ignored) {
    (void)ignored;
    pthread_attr_t attr;void *base=NULL;size_t size=0;
    if(pthread_getattr_np(pthread_self(),&attr)||pthread_attr_getstack(&attr,&base,&size)||pthread_attr_destroy(&attr)||size!=PTHREAD_STACK_MIN){lifecycle_result=778;return NULL;}
    uintptr_t here;__asm__ volatile("mov %0, sp":"=r"(here));
    lifecycle_base=(uintptr_t)base;lifecycle_top=lifecycle_base+size;lifecycle_painted=here-512;
    if(lifecycle_painted<lifecycle_base||here>lifecycle_top){lifecycle_result=779;return NULL;}
    for(uintptr_t p=lifecycle_base;p<lifecycle_painted;p++)*(volatile unsigned char *)p=0xa7;
    struct flock lock={.l_type=F_WRLCK,.l_whence=SEEK_SET,.l_start=0,.l_len=1};
    errno=0;lifecycle_result=fcntl(lifecycle_fd,7,&lock);lifecycle_errno=errno;
    lifecycle_peak=lifecycle_stack_peak();return NULL;
}
static int lifecycle_stage(void) {
    struct timespec tick={0,1000000};
    for(unsigned n=0;n<10000;n++){if(__atomic_load_n(&lifecycle_ready,__ATOMIC_ACQUIRE))return 1;nanosleep(&tick,NULL);}return 0;
}
static int lifecycle_collect(void) {
    struct flock query={.l_type=F_WRLCK,.l_whence=SEEK_SET,.l_start=0,.l_len=1};
    for(unsigned n=0;n<128;n++){
        if(fcntl(lifecycle_fd,F_GETLK,&query))return -21;
        int state=wait_lifecycle_recovered();if(state)return state;
        sched_yield();query.l_type=F_WRLCK;
    }return 0;
}
/* Root's argv dispatch calls this before the supervisor's ordinary cases. */
int public_wait_lifecycle_exec(int argc,char **argv) {
    if(argc!=3)return 71;
    int fd=0;for(char *p=argv[2];*p;p++){if(*p<'0'||*p>'9')return 72;fd=fd*10+*p-'0';}
    if(wait_lifecycle_count()!=0||fcntl(fd,F_GETFD)<0)return 73;
    struct flock lock={.l_type=F_WRLCK,.l_whence=SEEK_SET,.l_len=1};
    if(fcntl(fd,F_GETLK,&lock)||lock.l_type!=F_UNLCK)return 74;
    lock.l_type=F_WRLCK;
    if(fcntl(fd,F_SETLK,&lock)||close(fd))return 75;
    return 0;
}
static void lifecycle_reap(pid_t child) {
    int status=0;expect("lifecycle waitpid",waitpid(child,&status,0),child);
    expect("lifecycle normal exit",WIFEXITED(status)&&WEXITSTATUS(status)==0,1);
    /* 0xfff3 requires no lock records, while this fixture intentionally holds them. */
    expect("lifecycle actual Process Page is dead",process_lifetime(child),0);
}
static void public_wait_lifecycle(void) {
    lifecycle_fd=open("/tmp/public-wait-lifecycle",O_CREAT|O_RDWR,0666);
    expect("open lifecycle source",lifecycle_fd>=0,1);if(lifecycle_fd<0)return;
    int commands[2],replies[2];if(pipe(commands)||pipe(replies)){expect("lifecycle pipes",0,1);close(lifecycle_fd);return;}
    pid_t holder=fork();expect("fork lifecycle holder",holder>=0,1);
    if(holder==0){close(commands[1]);close(replies[0]);char command;
        while(read(commands[0],&command,1)==1){if(command=='Q')_exit(0);
            struct flock lock={.l_type=command=='L'?F_WRLCK:F_UNLCK,.l_whence=SEEK_SET,.l_len=1};
            if(fcntl(lifecycle_fd,F_SETLK,&lock)||write(replies[1],&command,1)!=1)_exit(96);
        }_exit(97);
    }
    close(commands[0]);close(replies[1]);if(holder<0){close(commands[1]);close(replies[0]);close(lifecycle_fd);return;}
    expect("lifecycle genuine PID blocker",wait_holder_exchange(commands[1],replies[0],'L'),1);
    struct sigaction action={0},previous;action.sa_handler=lifecycle_signal;sigemptyset(&action.sa_mask);
    expect("lifecycle engineering End handler",sigaction(SIGUSR1,&action,&previous),0);
    pthread_attr_t attr;expect("lifecycle attrs",pthread_attr_init(&attr),0);expect("lifecycle actual64K",pthread_attr_setstacksize(&attr,PTHREAD_STACK_MIN),0);
    unsigned long long previous_generation=0;
    for(unsigned turn=0;turn<20;turn++){
        unsigned mode=turn%2?2:1;
        __atomic_store_n(&lifecycle_ready,0,__ATOMIC_RELEASE);__atomic_store_n(&lifecycle_seen,0,__ATOMIC_RELEASE);lifecycle_result=777;lifecycle_peak=0;
        expect("arm observed real End WAIT",wait_lifecycle_arm(mode),0);
        pthread_t worker;int created=pthread_create(&worker,&attr,lifecycle_worker,NULL);expect("create End worker",created,0);if(created)break;
        expect("End owner accepted Sleeping",lifecycle_stage(),1);
        unsigned long long generation=wait_lifecycle_generation();expect("fresh full WAIT generation",generation>previous_generation,1);previous_generation=generation;
        if(mode==1){
            struct timespec tick={0,1000000};int waiting=0;
            for(unsigned n=0;n<10000;n++){waiting=wait_lifecycle_receiver_waiting();if(waiting)break;nanosleep(&tick,NULL);}
            expect("real private channel has blocked receiver",waiting,1);
            expect("true signal to waiting End owner",pthread_kill(worker,SIGUSR1),0);
        }
        void *result=NULL;expect("join actual End owner",pthread_join(worker,&result),0);expect("genuine pthread_exit marker",(int)(uintptr_t)result,1);
        if(mode==1)expect("End signal delivered",__atomic_load_n(&lifecycle_seen,__ATOMIC_ACQUIRE),SIGUSR1);
        expect("End never returns abandoned fcntl",lifecycle_result,777);
        expect("End painted path<=16K",lifecycle_peak>0&&lifecycle_peak<=16384,1);
        int recovered=lifecycle_collect();
        expect("ordinary GET pays exact End receipt and raw handle",recovered,1);
        if(recovered!=1){wait_lifecycle_disarm();break;}
        expect("source remains open without rescue close",fcntl(lifecycle_fd,F_GETFD)>=0,1);
        printf("posix-procs: WAIT End mode %u turn %u full generation %llu stack %zu bytes\n",mode,turn,generation,lifecycle_peak);
        wait_lifecycle_disarm();
    }
    /* A fresh live parent WAIT remains protected throughout genuine child fork/exec. */
    __atomic_store_n(&lifecycle_ready,0,__ATOMIC_RELEASE);lifecycle_result=777;lifecycle_peak=0;
    pid_t executed_child=-1;
    pthread_t worker;int created=1;
    if(wait_lifecycle_count()==0){
        expect("arm fork WAIT observation",wait_lifecycle_arm(3),0);
        created=pthread_create(&worker,&attr,lifecycle_worker,NULL);
        expect("create fork WAIT owner",created,0);
    }
    if(!created){
        expect("fork parent genuinely Sleeping",lifecycle_stage(),1);
        expect("fork parent exact raw and server debt",wait_lifecycle_still_sleeping(),1);
        pid_t child=fork();expect("fork while another thread waits",child>=0,1);
        if(child==0){
            if(wait_lifecycle_count()!=0||close(lifecycle_fd))_exit(76);
            int reused=open("/tmp/public-wait-lifecycle-reused",O_CREAT|O_RDWR,0666);
            if(reused!=lifecycle_fd)_exit(77);
            char number[24];snprintf(number,sizeof number,"%d",reused);
            char *arguments[]={"procs-child","wait-lifecycle-exec",number,NULL};char *environment[]={NULL};
            execve("/bin/procs-child",arguments,environment);_exit(78);
        }
        if(child>0){executed_child=child;lifecycle_reap(child);}
        expect("child close and exec preserve exact parent Sleeping",wait_lifecycle_still_sleeping(),1);
        expect("real unlock wakes surviving parent WAIT",wait_holder_exchange(commands[1],replies[0],'U'),1);
        expect("join surviving fork parent",pthread_join(worker,NULL),0);expect("parent WAIT canonical success",lifecycle_result,0);
        expect("fork parent painted path<=16K",lifecycle_peak>0&&lifecycle_peak<=16384,1);
        printf("posix-procs: WAIT fork parent stack %zu bytes\n",lifecycle_peak);
        expect("parent success pays exact receipt and raw channel",wait_lifecycle_recovered(),1);
    }
    wait_lifecycle_disarm();expect("restore lifecycle handler",sigaction(SIGUSR1,&previous,NULL),0);expect("destroy lifecycle attrs",pthread_attr_destroy(&attr),0);
    char quit='Q';expect("stop lifecycle holder",write(commands[1],&quit,1),1);close(commands[1]);close(replies[0]);lifecycle_reap(holder);
    /* Only after debt assertions: release successful parent PID lock and its fd. */
    expect("close completed lifecycle source",close(lifecycle_fd),0);
    expect("RAM holder lifetime after all locks released",ram_lifetime(holder),0);
    if(executed_child>0)expect("RAM exec child lifetime after all locks released",ram_lifetime(executed_child),0);
    if(!failures)printf("posix-procs: genuine WAIT End exact debts and live parent fork exec custody ok\n");
}

extern int wait_process_discover(int fd,unsigned pid,unsigned long long nonce);
extern int wait_process_receipt_gone(int fd,unsigned pid,unsigned long long nonce);
extern unsigned long long wait_process_owner(void);
extern int wait_process_ticks(void);
/* Root wires this only after genuine read-only RAM method 0xfff7 is present. */
void public_wait_process_exit(void) {
    lifecycle_fd=open("/tmp/public-wait-process-exit",O_CREAT|O_RDWR,0666);
    expect("open process-exit source",lifecycle_fd>=0,1);if(lifecycle_fd<0)return;
    int holder_commands[2],holder_replies[2];
    if(pipe(holder_commands)||pipe(holder_replies)){expect("process-exit holder pipes",0,1);close(lifecycle_fd);return;}
    pid_t holder=fork();expect("fork process-exit blocker",holder>=0,1);
    if(holder==0){close(holder_commands[1]);close(holder_replies[0]);char command;
        while(read(holder_commands[0],&command,1)==1){if(command=='Q')_exit(0);
            struct flock lock={.l_type=command=='L'?F_WRLCK:F_UNLCK,.l_whence=SEEK_SET,.l_len=1};
            if(fcntl(lifecycle_fd,F_SETLK,&lock)||write(holder_replies[1],&command,1)!=1)_exit(81);
        }_exit(82);
    }
    close(holder_commands[0]);close(holder_replies[1]);
    if(holder<0){close(holder_commands[1]);close(holder_replies[0]);close(lifecycle_fd);return;}
    expect("process-exit genuine blocker remains held",wait_holder_exchange(holder_commands[1],holder_replies[0],'L'),1);
    unsigned previous_pid=0;unsigned long long previous_owner=0;
    for(unsigned turn=0;turn<2;turn++){
        int control[2],ready[2];if(pipe(control)||pipe(ready)){expect("process-exit peer pipes",0,1);break;}
        pid_t peer=fork();expect("fork pending WAIT process",peer>=0,1);
        if(peer==0){
            close(control[1]);close(ready[0]);
            __atomic_store_n(&lifecycle_ready,0,__ATOMIC_RELEASE);
            if(wait_lifecycle_arm(3))_exit(83);
            pthread_attr_t attr;if(pthread_attr_init(&attr)||pthread_attr_setstacksize(&attr,PTHREAD_STACK_MIN))_exit(84);
            pthread_t worker;if(pthread_create(&worker,&attr,lifecycle_worker,NULL)||pthread_attr_destroy(&attr))_exit(84);
            if(!lifecycle_stage())_exit(85);
            struct timespec tick={0,1000000};int waiting=0;
            for(unsigned n=0;n<10000;n++){waiting=wait_lifecycle_receiver_waiting();if(waiting)break;nanosleep(&tick,NULL);}
            if(waiting!=1||write(ready[1],"W",1)!=1)_exit(86);
            char exit_permission=0;if(read(control[0],&exit_permission,1)!=1||exit_permission!='E')_exit(87);
            /* No join, source close, Cancel, Release or test-induced cancellation. */
            _exit(0);
        }
        close(control[0]);close(ready[1]);
        if(peer<0){close(control[1]);close(ready[0]);break;}
        char accepted=0;expect("child actual kernel WAIT before process exit",read(ready[0],&accepted,1),1);expect("child WAIT ready marker",accepted,'W');
        unsigned long long nonce=(2ULL<<32)|((unsigned long long)turn+1);
        struct timespec tick={0,1000000};int discovered=0;
        for(unsigned n=0;n<128;n++){discovered=wait_process_discover(lifecycle_fd,(unsigned)peer,nonce);if(discovered)break;nanosleep(&tick,NULL);}
        expect("discover actual full paid receipt before exit",discovered,1);
        if(discovered==1)expect("exact saved receipt is present before real exit",wait_process_receipt_gone(lifecycle_fd,(unsigned)peer,nonce),0);
        unsigned long long owner=wait_process_owner();expect("process-exit fresh full PID",(unsigned)peer!=previous_pid,1);expect("process-exit fresh full paid owner",owner!=0&&owner!=previous_owner,1);
        previous_pid=(unsigned)peer;previous_owner=owner;
        expect("authorize actual _exit with pending WAIT",write(control[1],"E",1),1);close(control[1]);close(ready[0]);lifecycle_reap(peer);
        int gone=0;
        if(discovered==1){
            for(unsigned n=0;n<128;n++){gone=wait_process_receipt_gone(lifecycle_fd,(unsigned)peer,nonce);if(gone)break;nanosleep(&tick,NULL);}
            expect("dead process exact Queue and both Pool halves absent",gone,1);
        }
        expect("parent source remains open through peer death",fcntl(lifecycle_fd,F_GETFD)>=0,1);
        struct flock get={.l_type=F_WRLCK,.l_whence=SEEK_SET,.l_len=1};expect("original blocker still real after process exit",fcntl(lifecycle_fd,F_GETLK,&get),0);expect("blocker stays Write",get.l_type,F_WRLCK);expect("blocker remains full holder PID",get.l_pid,holder);
        if(discovered!=1||gone!=1)break;
    }
    expect("process observer own dispatch bound",wait_process_ticks(),0);
    char quit='Q';expect("stop process-exit holder",write(holder_commands[1],&quit,1),1);close(holder_commands[1]);close(holder_replies[0]);lifecycle_reap(holder);
    expect("close process-exit source only after exact debt checks",close(lifecycle_fd),0);
    if(!failures)printf("posix-procs: genuine pending WAIT process exit retires exact paid receipt without rescue close ok\n");
}


/* Genuine arbitrary siglongjmp consumer; Root enables only with accepted pin. */
extern int wait_lifecycle_complete_success(void);
extern int wait_lifecycle_jump_marked(void);
static sigjmp_buf lifecycle_jump_target;
static volatile sig_atomic_t lifecycle_jump_seen;
static unsigned lifecycle_jump_turn, lifecycle_jump_ready, lifecycle_jump_complete;
static int lifecycle_jump_error;
static unsigned long long lifecycle_jump_previous_generation;
static void lifecycle_jump_signal(int signal) {
    lifecycle_jump_seen=signal;
    siglongjmp(lifecycle_jump_target,1);
}
void wait_lifecycle_jump_receive_stage(void) {
    __atomic_store_n(&lifecycle_jump_ready,__atomic_load_n(&lifecycle_jump_turn,__ATOMIC_ACQUIRE),__ATOMIC_RELEASE);
}
void wait_lifecycle_jump_complete_stage(void) {
    __atomic_store_n(&lifecycle_jump_complete,1,__ATOMIC_RELEASE);
    /* A distinct sender supplies the real signal after canonical server success. */
    while(lifecycle_jump_seen!=SIGUSR1)sched_yield();
}
__attribute__((noinline)) static int lifecycle_deeper_wait(void) {
    volatile unsigned char workspace[256];
    for(unsigned i=0;i<sizeof workspace;i++)workspace[i]=(unsigned char)i;
    struct flock lock={.l_type=F_WRLCK,.l_whence=SEEK_SET,.l_len=1};
    int result=fcntl(lifecycle_fd,7,&lock);
    /* Keep this genuine deeper caller frame live across the WAIT operation. */
    if(workspace[17]!=17)return -2;
    return result;
}
static void *lifecycle_jump_worker(void *ignored) {
    (void)ignored;
    pthread_attr_t attr;void *base=NULL;size_t size=0;
    if(pthread_getattr_np(pthread_self(),&attr)||pthread_attr_getstack(&attr,&base,&size)||pthread_attr_destroy(&attr)||size!=PTHREAD_STACK_MIN)return (void *)101;
    uintptr_t here;__asm__ volatile("mov %0, sp":"=r"(here));
    lifecycle_base=(uintptr_t)base;lifecycle_top=lifecycle_base+size;lifecycle_painted=here-512;
    if(lifecycle_painted<lifecycle_base||here>lifecycle_top)return (void *)102;
    for(uintptr_t p=lifecycle_base;p<lifecycle_painted;p++)*(volatile unsigned char *)p=0xa7;
    for(;;){
        unsigned turn=__atomic_load_n(&lifecycle_jump_turn,__ATOMIC_ACQUIRE);
        if(turn>=21)break;
        lifecycle_jump_seen=0;
        __atomic_store_n(&lifecycle_ready,0,__ATOMIC_RELEASE);
        __atomic_store_n(&lifecycle_jump_ready,UINT_MAX,__ATOMIC_RELEASE);
        if(sigsetjmp(lifecycle_jump_target,1)==0){
            if(wait_lifecycle_arm(turn==20?5:4)){__atomic_store_n(&lifecycle_jump_error,103,__ATOMIC_RELEASE);return (void *)103;}
            (void)lifecycle_deeper_wait();
            __atomic_store_n(&lifecycle_jump_error,104,__ATOMIC_RELEASE);return (void *)104;
        }
        /* Automatic turn is reread: only globals survive modification at jump. */
        turn=__atomic_load_n(&lifecycle_jump_turn,__ATOMIC_ACQUIRE);
        if(lifecycle_jump_seen!=SIGUSR1){__atomic_store_n(&lifecycle_jump_error,105,__ATOMIC_RELEASE);return (void *)105;}
        unsigned long long generation=wait_lifecycle_generation();
        if(generation<=lifecycle_jump_previous_generation){__atomic_store_n(&lifecycle_jump_error,106,__ATOMIC_RELEASE);return (void *)106;}
        lifecycle_jump_previous_generation=generation;
        if(wait_lifecycle_jump_marked()!=1){__atomic_store_n(&lifecycle_jump_error,114,__ATOMIC_RELEASE);return (void *)114;}
        if(turn==20&&wait_lifecycle_complete_success()!=1){__atomic_store_n(&lifecycle_jump_error,107,__ATOMIC_RELEASE);return (void *)107;}
        int recovered=lifecycle_collect();
        if(recovered!=1){__atomic_store_n(&lifecycle_jump_error,108,__ATOMIC_RELEASE);return (void *)108;}
        if(fcntl(lifecycle_fd,F_GETFD)<0){__atomic_store_n(&lifecycle_jump_error,109,__ATOMIC_RELEASE);return (void *)109;}
        lifecycle_peak=lifecycle_stack_peak();
        if(lifecycle_peak==0||lifecycle_peak>16384){__atomic_store_n(&lifecycle_jump_error,110,__ATOMIC_RELEASE);return (void *)110;}
        printf("posix-procs: WAIT arbitrary jump same owner turn %u full generation %llu stack %zu bytes\n",turn,generation,lifecycle_peak);
        wait_lifecycle_disarm();
        __atomic_store_n(&lifecycle_jump_turn,turn+1,__ATOMIC_RELEASE);
    }
    return NULL;
}
static int lifecycle_jump_stage(unsigned turn) {
    struct timespec tick={0,1000000};
    for(unsigned n=0;n<10000;n++){
        if(__atomic_load_n(&lifecycle_jump_ready,__ATOMIC_ACQUIRE)==turn)return 1;
        if(__atomic_load_n(&lifecycle_jump_error,__ATOMIC_ACQUIRE))return 0;
        nanosleep(&tick,NULL);
    }return 0;
}
/* Root calls only after accepted arbitrary-jump callback + WAIT consumer. */
void public_wait_arbitrary_jumps(void) {
    lifecycle_fd=open("/tmp/public-wait-arbitrary-jump",O_CREAT|O_RDWR,0666);
    expect("open arbitrary jump stable source",lifecycle_fd>=0,1);if(lifecycle_fd<0)return;
    int commands[2],replies[2];if(pipe(commands)||pipe(replies)){expect("arbitrary jump pipes",0,1);close(lifecycle_fd);return;}
    pid_t parent=getpid(),holder=fork();expect("fork arbitrary jump real blocker",holder>=0,1);
    if(holder==0){close(commands[1]);close(replies[0]);char command;
        while(read(commands[0],&command,1)==1){
            if(command=='Q')_exit(0);
            if(command=='C'){
                struct flock get={.l_type=F_WRLCK,.l_whence=SEEK_SET,.l_len=1};
                char answer=fcntl(lifecycle_fd,F_GETLK,&get)==0&&get.l_type==F_WRLCK&&get.l_pid==parent?'C':'X';
                if(write(replies[1],&answer,1)!=1)_exit(111);
                continue;
            }
            struct flock lock={.l_type=command=='L'?F_WRLCK:F_UNLCK,.l_whence=SEEK_SET,.l_len=1};
            if(fcntl(lifecycle_fd,F_SETLK,&lock)||write(replies[1],&command,1)!=1)_exit(112);
        }_exit(113);
    }
    close(commands[0]);close(replies[1]);if(holder<0){close(commands[1]);close(replies[0]);close(lifecycle_fd);return;}
    expect("arbitrary jump genuine blocker stays held",wait_holder_exchange(commands[1],replies[0],'L'),1);
    struct sigaction action={0},previous;action.sa_handler=lifecycle_jump_signal;sigemptyset(&action.sa_mask);
    expect("install genuine arbitrary jump handler",sigaction(SIGUSR1,&action,&previous),0);
    lifecycle_jump_seen=0;lifecycle_jump_error=0;lifecycle_jump_previous_generation=0;
    __atomic_store_n(&lifecycle_jump_turn,0,__ATOMIC_RELEASE);
    __atomic_store_n(&lifecycle_jump_ready,UINT_MAX,__ATOMIC_RELEASE);
    __atomic_store_n(&lifecycle_jump_complete,0,__ATOMIC_RELEASE);
    pthread_attr_t attr;expect("jump worker attrs",pthread_attr_init(&attr),0);expect("jump actual64K",pthread_attr_setstacksize(&attr,PTHREAD_STACK_MIN),0);
    pthread_t worker;int created=pthread_create(&worker,&attr,lifecycle_jump_worker,NULL);expect("create same owner jump worker",created,0);
    if(!created){
        for(unsigned turn=0;turn<21;turn++){
            int stage=lifecycle_jump_stage(turn);expect("same owner deeper WAIT reached real stage",stage,1);if(!stage)break;
            struct timespec tick={0,1000000};int waiting=0;
            for(unsigned n=0;n<10000;n++){waiting=wait_lifecycle_receiver_waiting();if(waiting)break;nanosleep(&tick,NULL);}
            expect("jump from actual blocked private Receive",waiting,1);
            if(turn==20){
                expect("unlock before canonical success jump",wait_holder_exchange(commands[1],replies[0],'U'),1);
                unsigned ready=0;for(unsigned n=0;n<10000;n++){ready=__atomic_load_n(&lifecycle_jump_complete,__ATOMIC_ACQUIRE);if(ready)break;nanosleep(&tick,NULL);}
                expect("strict decoded Complete precedes jump",ready,1);
            }
            expect("actual sibling pthread_kill causes arbitrary jump",pthread_kill(worker,SIGUSR1),0);
        }
        void *result=NULL;expect("join live owner after21 jumps",pthread_join(worker,&result),0);expect("same owner jump cleanup marker",(int)(uintptr_t)result,0);expect("same owner no cleanup error",__atomic_load_n(&lifecycle_jump_error,__ATOMIC_ACQUIRE),0);
        expect("more than16 exact jump cycles completed",__atomic_load_n(&lifecycle_jump_turn,__ATOMIC_ACQUIRE),21);
        expect("other PID observes success survived jump cleanup",wait_holder_exchange(commands[1],replies[0],'C'),1);
    }
    wait_lifecycle_disarm();expect("restore arbitrary jump handler",sigaction(SIGUSR1,&previous,NULL),0);expect("destroy jump attrs",pthread_attr_destroy(&attr),0);
    char quit='Q';expect("stop jump holder after debt checks",write(commands[1],&quit,1),1);close(commands[1]);close(replies[0]);lifecycle_reap(holder);
    struct flock unlock={.l_type=F_UNLCK,.l_whence=SEEK_SET,.l_len=1};expect("unlock preserved canonical success after assertions",fcntl(lifecycle_fd,F_SETLK,&unlock),0);
    expect("close unchanged jump source after all exact debts",close(lifecycle_fd),0);
    if(!failures)printf("posix-procs: genuine21 arbitrary WAIT jumps same owner and canonical success preserve exact debts ok\n");
}

/* Separately activated only after the corrected callback pin is accepted. */
extern int wait_cleanup_pending_rotation(unsigned fd);
void public_wait_pending_rotation(void) {
    int fd=open("/tmp/public-wait-pending-rotation",O_CREAT|O_RDWR,0666);
    expect("pending rotation actual source",fd>=0,1);if(fd<0)return;
    int commands[2],replies[2];
    if(pipe(commands)||pipe(replies)){expect("pending rotation pipes",0,1);close(fd);return;}
    pid_t holder=fork();expect("pending rotation blocker PID",holder>=0,1);
    if(holder==0){close(commands[1]);close(replies[0]);char command;
        while(read(commands[0],&command,1)==1){if(command=='Q')_exit(0);
            struct flock lock={.l_type=command=='L'?F_WRLCK:F_UNLCK,.l_whence=SEEK_SET,.l_len=1};
            if(fcntl(fd,F_SETLK,&lock)||write(replies[1],&command,1)!=1)_exit(108);
        }_exit(109);
    }
    close(commands[0]);close(replies[1]);
    if(holder<0){close(commands[1]);close(replies[0]);close(fd);return;}
    expect("pending rotation genuine held blocker",wait_holder_exchange(commands[1],replies[0],'L'),1);
    expect("real Interrupted preserves early debt while paying later channel",wait_cleanup_pending_rotation((unsigned)fd),1);
    expect("pending source survives without rescue close",fcntl(fd,F_GETFD)>=0,1);
    expect("pending rotation normal unlock",wait_holder_exchange(commands[1],replies[0],'U'),1);
    char quit='Q';expect("pending rotation holder stop",write(commands[1],&quit,1),1);
    close(commands[1]);close(replies[0]);lifecycle_reap(holder);
    expect("pending rotation final source close",close(fd),0);
    if(!failures)printf("posix-procs: WAIT real deferred pending physical cleanup rotation ok\n");
}
