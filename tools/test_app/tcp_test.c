
#include <error.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>

#define MAX_MSG_SIZE 1024
#define TCP_PORT     60001
static int tcp_nodelay = -1;
static int tcp_bufsize = 0;
static int statis_interval = 5000;

int run_as_rx(int tcp_port)
{
    char msg[MAX_MSG_SIZE];
    struct timeval   tm1, tm2;
    struct timezone  tz;
    unsigned int duration = 0;
    unsigned int rx_total_len = 0;
    int tcp_sock = -1, cli_sock = -1;
    socklen_t addr_len = 0;
    int rlen = 0;
    struct sockaddr_in remote_addr, local_addr;

    printf("run as tcp receiver, port:%d ...\n", tcp_port);
    addr_len = sizeof(struct sockaddr_in);
    tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_sock < 0) {
        printf("create tcp socket error:%s\n", strerror(errno));
        exit(1);
    }

    if (tcp_bufsize > 0) {
        setsockopt(tcp_sock, SOL_SOCKET, SO_RCVBUF, (void *)&tcp_bufsize, sizeof(tcp_bufsize));
    }

    //bind local address
    bzero(&local_addr, addr_len);
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    local_addr.sin_port = htons(tcp_port);
    if (bind(tcp_sock, (struct sockaddr *)&local_addr, addr_len) < 0) {
        printf("tcp bind error:%s\n", strerror(errno));
        close(tcp_sock);
        exit(1);
    }

    if (listen(tcp_sock, 20) < 0) {
        printf("tcp listen error:%s\n", strerror(errno));
        close(tcp_sock);
        exit(1);
    }

    while (1) {
        cli_sock = accept(tcp_sock, (struct sockaddr *)&remote_addr, &addr_len);
        if (cli_sock > 0) {
            printf("accept new connection ...\r\n");
            rx_total_len = 0;
            if (tcp_bufsize > 0) {
                setsockopt(cli_sock, SOL_SOCKET, SO_RCVBUF, (void *)&tcp_bufsize, sizeof(tcp_bufsize));
            }
            gettimeofday(&tm1, &tz);
            do {
                rlen = recv(cli_sock, msg, MAX_MSG_SIZE, 0);
                if (rlen > 0) { rx_total_len += rlen; }
                gettimeofday(&tm2, &tz);
                duration = (tm2.tv_sec-tm1.tv_sec)*1000+(tm2.tv_usec-tm1.tv_usec)/1000;
                if (duration >= statis_interval) {
                    printf("TCP trans speed: %dKB/s (%d:%d)\n", 
                                (((rx_total_len/1024)*1000)/duration),  rx_total_len, duration);
                    gettimeofday(&tm1, &tz);
                    rx_total_len = 0;
                }
            } while (rlen > 0);

            close(cli_sock);
            printf("TCP trans over!\r\n");
        } else {
            sleep(1);
        }
    }

    close(tcp_sock);
}

int run_as_tx(int tcp_port, char *rx_ip)
{
    int ret = 0;
    char msg[MAX_MSG_SIZE];
    int tcp_sock = -1;
    socklen_t addr_len = 0;
    struct sockaddr_in remote_addr, local_addr;
    struct timeval   tm1, tm2;
    struct timezone  tz;
    struct timeval timeout;
    long duration = 0;
    unsigned int tx_total_len = 0;

    printf("run as tcp transmitter, receiver ip:%s\n", rx_ip);
    addr_len = sizeof(struct sockaddr_in);
    tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_sock < 0) {
        printf("socket create error:%s\n", strerror(errno));
        exit(1);
    }

    if (tcp_bufsize > 0) {
        setsockopt(tcp_sock, SOL_SOCKET, SO_SNDBUF, (void *)&tcp_bufsize, sizeof(tcp_bufsize));
    }
    if (tcp_nodelay != -1) {
        setsockopt(tcp_sock, IPPROTO_TCP, TCP_NODELAY, (void *)&tcp_nodelay, sizeof(tcp_nodelay));
    }
    bzero(&local_addr, addr_len);
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    local_addr.sin_port = 0;//htons(tcp_port + 1);
    if (bind(tcp_sock, (struct sockaddr *)&local_addr, addr_len) < 0) {
        printf("tcp bind error:[%d:%s], port:%d\n", errno, strerror(errno), tcp_port + 1);
        exit(1);
    }

    bzero(&remote_addr, addr_len);
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_addr.s_addr = inet_addr(rx_ip);
    remote_addr.sin_port = htons(tcp_port);
    if (connect(tcp_sock, (struct sockaddr *)&remote_addr, addr_len) != 0) {
        printf("tcp connect to %s failed, error:[%d:%s]\n", rx_ip, errno, strerror(errno));
        close(tcp_sock);
        exit(1);
    }

    printf("tcp connect to %s ok, start tx ...\n", rx_ip);
    while (1) {
        ret = send(tcp_sock, msg, sizeof(msg), 0);
        if (ret != sizeof(msg)) {
            printf("tcp send error:[%d:%s]\n", errno, strerror(errno));
            break;
        } else {
            tx_total_len += ret;
            gettimeofday(&tm2, &tz);
            duration = (tm2.tv_sec-tm1.tv_sec)*1000+(tm2.tv_usec-tm1.tv_usec)/1000;
            if (duration >= statis_interval) {
                printf("TCP trans speed: %dKB/s (%d:%d)\n", 
                            (((tx_total_len/1024)*1000)/duration),  tx_total_len, duration);
                gettimeofday(&tm1, &tz);
                tx_total_len = 0;
            }
        }
    }
    close(tcp_sock);
}

int main(int argc, char *argv[])
{
    char *rx_ip = NULL;
    int   port   = TCP_PORT;
    int   i = 1;

    printf("Usage: tcp_test [port] [ipaddr]\r\n");
    while (i < argc) {
        if (strchr(argv[i], '.')) {
            rx_ip = argv[i];
        } else if (strcmp(argv[i], "N") == 0) {
            tcp_nodelay = 1;
        } else if (strcmp(argv[i], "S") == 0) {
            tcp_bufsize = atoi(argv[i + 1]);
            i++;
        } else if (strcmp(argv[i], "i") == 0) {
            statis_interval = atoi(argv[i + 1]);
            i++;
        } else if (atoi(argv[i]) > 0) {
            port = atoi(argv[i]);
        }
        i++;
    }

    if (rx_ip) {
        run_as_tx(port, rx_ip);
    } else {
        run_as_rx(port);
    }
}

