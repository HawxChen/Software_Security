#ifndef _HTTPDEF_H_
#define _HTTPDEF_H_
#include<sys/types.h>
#include<sys/socket.h>
#include<ctype.h>

#include<netinet/in.h>
#include<unistd.h>
#include<errno.h>
#include <limits.h>
#include<sys/select.h>
#include<pthread.h>
#include<unistd.h>
#include<signal.h>
#include<stdlib.h>
#include<string.h>
#include<stdio.h>
#include<netdb.h>
#include<stdarg.h>
#include<pthread.h>
#define BUFSIZE_DEFAULT (8192)
const int TRUE = 1;
const int FALSE = 0;
const char* pattern_tail = " HTTP/1.1\r\n";
const int  pattern_tail_len = 11;
const char* pattern_head = "GET /exec/";
const int  pattern_head_len = 10;
const char* pattern_get = "GET /";
const int  pattern_get_len = 5;
const char* pattern_ending = "\r\n\r\n";
const int pattern_ending_len = 4;
const char* pattern_exec = "/exec/";
const int pattern_exec_len = 6;
#define pattern_line_ending ("\r\n")
#define pattern_line_ending_len (2)
extern int errno;
int errexit(const char* format, ...);
unsigned short portbase = 0;
int passivesock(const char*service, const char* transport, int qlen);
int echo(int fd);
int TRACE_PRINT(const char* format, ...);
int DEBUG_PRINT(const char* format, ...);
struct io_struct {
    char* buf;
    char* cmd;
    int ret;
    int fd;
    int id;
    int size;
    int accu;
    int pipefd[2];
};
struct io_struct* conns[FD_SETSIZE];

void ok_request(int client, struct io_struct* conn) {
    char buf[1024];
//    TRACE_PRINT("ok_request, fd:%d, %s\n",client, result);
#ifdef __PURE_BODY__
    sprintf(buf, "HTTP/1.1 200 OK\r\n");
    write(client, buf, strlen(buf));
    sprintf(buf, "Content-Type: text/plain\r\n");
    write(client, buf, strlen(buf));
    sprintf(buf, "Content-Length: %d\r\n", conn->accu);
    write(client, buf, strlen(buf));
    sprintf(buf, "\r\n");
    write(client, buf, strlen(buf));

    write(client, conn->buf, conn->accu);

#else
    sprintf(buf, "HTTP/1.1 200 OK\r\n");
    write(client, buf, strlen(buf));
    sprintf(buf, "Content-Type: text/html\r\n");
    write(client, buf, strlen(buf));
    char* TITLE = "<HTML><TITLE>OK</TITLE>\r\n";
    char* BODY_HEAD = "<BODY><P>\r\n";
    char* BODY_TAIL = "<P></BODY></HTML>\r\n";
    sprintf(buf, "Content-Length: %zd\r\n", strlen(result)+strlen(BODY_HEAD)+strlen(BODY_TAIL)+strlen(TITLE));
    write(client, buf, strlen(buf));
    sprintf(buf, "\r\n");
    write(client, buf, strlen(buf));

    sprintf(buf, TITLE);
    write(client, buf, strlen(buf));

    sprintf(buf, BODY_HEAD);
    write(client, buf, strlen(buf));

    write(client, conn->buf, conn->accu);

    sprintf(buf, BODY_TAIL);
    write(client, buf, strlen(buf));
#endif
}
void bad_request(int client, struct io_struct* conn) {
    const int buf_size = 1024;
    char buf[buf_size];
//    TRACE_PRINT("bad_request, fd:%d, %s\n",client, output);
#ifdef __PURE_BODY__
    sprintf(buf, "HTTP/1.1 404 NOT FOUND\r\n");
    write(client, buf, strlen(buf));
    sprintf(buf, "Content-Type: text/plain\r\n");
    write(client, buf, strlen(buf));
    sprintf(buf, "Content-Length: %d\r\n", conn->accu);
    write(client, buf, strlen(buf));
    sprintf(buf, "\r\n");
    write(client, buf, strlen(buf));

    write(client, conn->buf, conn->accu);
#else
    sprintf(buf, "HTTP/1.1 404 NOT FOUND\r\n");
    write(client, buf, strlen(buf));
    sprintf(buf, "cache-control: no-cache\r\n");
    write(client, buf, strlen(buf));
    sprintf(buf, "Content-Type: text/html\r\n");
    write(client, buf, strlen(buf));
    char*TITLE = "<HTML><TITLE>Not Found</TITLE>\r\n";
    char*BODY_HEAD = "<BODY><P>\r\n"; 
    char*BODY_TAIL = "</BODY></HTML>\r\n"; 
    sprintf(buf, "Content-Length: %zd\r\n", strlen(output)+strlen(BODY_HEAD)+strlen(BODY_TAIL)+strlen(TITLE));
    write(client, buf, strlen(buf));
    sprintf(buf, "\r\n");
    write(client, buf, strlen(buf));

    sprintf(buf,TITLE);
    write(client, buf, strlen(buf));

    sprintf(buf, BODY_HEAD);
    write(client, buf, strlen(buf));

    write(client, conn->buf, conn->accu);

    sprintf(buf,BODY_TAIL);
    write(client, buf, strlen(buf));
#endif
}
int passiveTCP(char* service, int qlen) {
    return passivesock(service, "tcp", qlen);
}
int DEBUG_PRINT(const char* format, ...) {
#ifdef __DEBUG__
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fprintf(stderr,"--my_pid:%d\n", (int)getpid());
    fflush(stderr);
#endif
    return 0;
}
int TRACE_PRINT(const char* format, ...) {
#ifdef __TRACE__
    fprintf(stderr,"my_pid:%d: ", (int)getpid());
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    fprintf(stderr,"\n");
    va_end(args);
    fflush(stderr);
#endif
    return 0;
}
//Internetworking with TCP/IP Vol. II: ANSI C Version: Design, Implementation, and Internals (3rd Edition)//ISBN-13: 978-0139738432 ISBN-10: 0139738436 
int passivesock(const char*service, const char* transport, int qlen) {
    struct servent *pse; /* pointer to service information entry */
    struct protoent* ppe; /* pointer to protocol information entry */
    struct sockaddr_in sin; /* socket descriptor and socket type */
    int sock_fd, sock_type; /*socket descriptor and socket type */

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;

    /*Map service name to port number*/
    if( (pse = getservbyname(service, transport))) {
        sin.sin_port = htons(ntohs((unsigned short)pse->s_port) + portbase);
    } else if( (sin.sin_port = htons((unsigned short)atoi(service))) == 0) {
        errexit("can not get \"%s\" service entry\n", service);
    }

    /*Map protocol name to protocol number*/
    if( (ppe = getprotobyname(transport)) == NULL) {
        errexit("can't get \"%s\" protocol entry\n", transport);
    }

    /*Use protocol to choose a socket type */
    if(strcmp(transport, "udp") == 0) {
        sock_type = SOCK_DGRAM;
    } else {
        sock_type = SOCK_STREAM;
    }

    /* Allocate a socket */
    sock_fd = socket(PF_INET, sock_type, ppe->p_proto);
    if(sock_fd < 0) {
        errexit("can't create socket: %s\n", strerror(errno));
    }

    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) < 0) {
        errexit("accept: %s\n", strerror(errno));
    }

    /*Bind the socket */
    if(bind(sock_fd, (struct sockaddr*) &sin, sizeof(sin)) < 0) {
        errexit("can't bind to %s port: %s\n", service, strerror(errno));
    }

    if( sock_type == SOCK_STREAM && listen(sock_fd, qlen) < 0) {
        errexit("can't listen on %s port: %s\n", service, strerror(errno));
    }

    return sock_fd;
}


# if 0
/*for multi-proceses version*/
void reaper(int sig)
{
    int status;
    while (wait3(&status, WNOHANG, (struct rusage *)0) >= 0){
        /* empty */;
    }
}
#endif 

int errexit(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    exit(1);
}
#endif
