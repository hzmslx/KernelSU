#include "klog.h"

#include "linux/kernel.h"
#include "linux/module.h"
#include "linux/init.h"
#include "linux/kthread.h"
#include "linux/delay.h"

#include "linux/errno.h"
#include "linux/types.h"

#include "linux/net.h"
#include "linux/inet.h"
#include "linux/socket.h"
#include "linux/in.h"

// get pid
#include "linux/sched/signal.h"

static struct task_struct *thread = NULL;

// bool isCreateSock = false;

/*pid_t get_pid_by_name(const char* process_name) {
    struct task_struct* tasks;
    pid_t pid = -1;

    read_lock(&tasklist_lock);
    for_each_process(tasks) {
        // 比较进程的命令行参数
        if (strcmp(tasks->comm, process_name) == 0) {
            pid = task_pid_nr(tasks);
            break;
        }
    }
    read_unlock(&tasklist_lock);

    return pid;
}*/

/*static int server_thread() {
    struct socket *sock, *client_sock;
    struct sockaddr_in s_addr;

    memset(&s_addr,0,sizeof(s_addr));
    s_addr.sin_family = AF_INET;
    s_addr.sin_port = htons(8080);
    s_addr.sin_addr.s_addr = in_aton("10.10.10.195");

    sock = (struct socket *)kmalloc(sizeof(struct socket),GFP_KERNEL);
    client_sock = (struct socket *)kmalloc(sizeof(struct socket),GFP_KERNEL);

    int ret = sock_create_kern(&init_net,AF_INET, SOCK_STREAM,0,&sock);
    if(ret < 0){
        printk("[SockTest]:socket_create_kern error!\n");
        return -1;
    }
    printk("[SockTest]:socket_create_kern ok!\n");

}*/


static struct task_struct *listen_thread = NULL;
static struct socket *listen_socket = NULL;

bool isCreateSock = false;
bool isBindServer= false;
bool isListenSock = false;

char *inet_ntoa(struct in_addr *in)
{
    char *str_ip = NULL;
    u_int32_t int_ip = 0;

    str_ip = kmalloc(16 * sizeof(char), GFP_KERNEL);

    if(!str_ip)
        return NULL;
    else
        memset(str_ip, 0, 16);

    int_ip = in->s_addr;

    sprintf(str_ip, "%d.%d.%d.%d", (int_ip) & 0xFF, (int_ip >> 8) & 0xFF,
            (int_ip >> 16) & 0xFF, (int_ip >> 16) & 0xFF);

    return str_ip;
}

int tcp_server_listen(void *unused) {

    while(!kthread_should_stop())
    {


        if(isCreateSock == false)
        {
            int server_err = sock_create_kern(&init_net,AF_INET, SOCK_STREAM, IPPROTO_TCP, &listen_socket);
            if(server_err < 0) {
                pr_warn("failed to create socket: %d\n", server_err);
                msleep(3000);
                continue;
            }
            isCreateSock = true;
        } else {

            if(isBindServer == false)
            {
                struct sockaddr_in server;
                server.sin_addr.s_addr = INADDR_ANY;
                server.sin_family = AF_INET;
                server.sin_port = htons(8181);

                int server_err = kernel_bind(listen_socket, (struct sockaddr*)&server,sizeof(server));
                if(server_err < 0) {
                    pr_warn("failed to bind server: %d\n", server_err);
                    msleep(3000);
                    continue;
                }
                isBindServer = true;
            } else {
                if(isListenSock == false) {
                    int server_err = kernel_listen(listen_socket, 5);
                    if(server_err < 0) {
                        pr_warn("failed to listen socket: %d\n", server_err);
                        msleep(3000);
                        continue;
                    }
                    isListenSock = true;
                } else {
                    while(true) {
                        struct socket *remote_socket = NULL;
                        int server_err = kernel_accept(listen_socket,&remote_socket,O_NONBLOCK);
                        if(server_err < 0) {
                            pr_warn("failed to accept socket: %d\n", server_err);
                            msleep(3000);
                            break;
                        }
                        else {
                            struct sockaddr_storage  client_addr;
                            int getnameErr = kernel_getsockname(remote_socket, (struct sockaddr*)&client_addr);
                            if(getnameErr < 0) {
                                pr_info("getnameErr: %d\n", getnameErr);
                                break;
                            }

                            if(client_addr.ss_family == AF_INET){
                                struct in_addr *ipv4 = (struct in_addr *)&client_addr;
                                char *ip = inet_ntoa(ipv4);
                                if(ip){
                                    pr_info("connect client ip: %s\n", ip);
                                    kfree(ip);
                                }

                                char *send_buf = NULL;
                                send_buf = kmalloc(1024, GFP_KERNEL);
                                if (send_buf == NULL) {
                                    pr_info("send_buf kmalloc error!\n");
                                    continue;
                                }
                                struct kvec send_vec;
                                struct msghdr send_msg;
                                memset(send_buf, 'a', 1024);
                                memset(&send_msg, 0, sizeof(send_msg));
                                memset(&send_vec, 0, sizeof(send_vec));
                                int send_err = kernel_sendmsg(remote_socket,&send_msg,&send_vec,1,1024);
                                kfree(send_buf);
                                if(send_err < 0){
                                    pr_info("kernel send msg error: %d\n", send_err);
                                    continue;
                                }
                                kernel_sock_shutdown(remote_socket,SHUT_RDWR);
                                sock_release(remote_socket);
                            }
                        }
                    }
                }

            }


        }

    }
}

int tcp_server_start(void) {

    listen_thread = kthread_run((void *) tcp_server_listen, NULL, "tcp-server");
    if (IS_ERR(listen_thread)) {
        pr_info("failed to create server thread\n");
        return PTR_ERR(listen_thread);
    }
    return 0;
}

int ktg_core_init(void) {
    tcp_server_start();
    return 0;
}

int ktg_core_exit(void) {
    return 0;
}