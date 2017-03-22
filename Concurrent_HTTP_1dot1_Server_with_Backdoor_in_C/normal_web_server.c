#include "util.h"
#define QLEN (1024) /* maximum connection queue length */
fd_set  rfds;            /* read file descriptor set */
fd_set  afds;            /* active file descriptor set */
int nfds;

void sig_handler(int sig) {
    switch (sig) {
        case SIGINT:
            TRACE_PRINT("SIG INT: %d\n", getpid() );
            for(int fd = 3; fd < nfds; fd++) {
                close(fd);
                FD_CLR(fd, &afds);
            }
            rfds = afds;
            exit(0);
            break;


    }
}
int exec_io(int fd) {
   int ret;
   ret = child_func(fd);
//   ret = echo(fd);
   return ret;
}
int main(int argc, char* argv[]) {
    char* service = "normal_web_server";
    struct sockaddr_in fsin; /* the from address of a client */
    struct sigaction act;
    sigset_t set;
    int msock;               /* master server socket */
    int ssock;               /* client socket */
    socklen_t alen;                /* from-address length */
    int ret_code = 0;

    printf("%d\n", FD_SETSIZE);
    switch (argc) {
        case    1:
            break;
        case    2:
                service = argv[1];
            break;
        default:
            errexit("usage: TCPmechod [port]\n");
    }

    msock = passiveTCP(service, QLEN);
    TRACE_PRINT("Server Is On");

    sigemptyset(&set);
    sigaddset(&set, SIGINT);
//    sigprocmask(SIG_BLOCK, &set, NULL);
//    sigprocmask(SIG_UNBLOCK, &set, NULL);

    bzero(&act, sizeof(struct sigaction));
    act.sa_mask = set;
    act.sa_handler = sig_handler;
    act.sa_flags = 0;
    sigaction(SIGINT, &act, NULL);

    //nfds = getdtablesize();
    nfds = msock+1;
    FD_ZERO(&afds);
    FD_SET(msock, &afds);

    while (1) {

        rfds = afds;
        if (0 > (ret_code = select(nfds, &rfds, (fd_set *) 0, (fd_set *) 0, (struct timeval *) 0)) ) {
            if(errno == EINTR) continue;
            errexit("select: %s, ret_code: %d\n", strerror(errno), ret_code); 
        }

        if (FD_ISSET(msock, &rfds)) {

            alen = sizeof(fsin);
            ssock = accept(msock, (struct sockaddr *)&fsin, &alen);

            if (ssock < 0) {
                errexit("accept: %s\n", strerror(errno));
            }

            FD_SET(ssock, &afds);

            if(nfds == ssock) nfds+=1;
        }

        for (int fd=0; fd<nfds; ++fd) {

            if (fd == msock || !FD_ISSET(fd, &rfds)) continue;

//                TRACE_PRINT("\t-------->fd:%d In<-------------", fd);

                if(exec_io(fd) > 0) continue;

//                TRACE_PRINT("\t-------->fd:%d Out<-------------", fd);
                close(fd);
                FD_CLR(fd, &afds);
                release_conn_ds(fd);
        }
    }

    return 0;
}
