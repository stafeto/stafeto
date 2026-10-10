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
