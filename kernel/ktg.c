#include "klog.h"

#include "linux/kernel.h"
#include "linux/module.h"
#include "linux/kthread.h"
#include "linux/delay.h"

#include "linux/init.h"
#include "linux/net.h"
#include "linux/inet.h"
#include "linux/socket.h"
#include "linux/inetdevice.h"
#include "linux/in.h"

// get pid
#include "linux/sched/signal.h"

static struct task_struct *thread = NULL;

bool isCreateSock = false;

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

static int
tgame_callback(void *unused) {
    struct socket *sock = NULL;
    struct sockaddr_in addr;

    while (!kthread_should_stop()) {

        msleep(3000);

        if(isCreateSock == false) {
            int ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
            if (ret < 0) {
                pr_warn("failed to create socket: %d\n", ret);
                continue;
            } else{
                isCreateSock = true;
                pr_info("success create socket!\n");
            }
        } else {
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = in_aton("192.168.50.104");
            addr.sin_port = htons(8080);

            int ret = sock->ops->connect(sock, (struct sockaddr *) &addr, sizeof(addr), 0);
            if (ret < 0) {
                pr_warn("failed to connect: %d\n", ret);
                sock_release(sock);
                isCreateSock = false;
                continue;
            } else {
                pr_info("success connect!\n");
                sock->ops->shutdown(sock, SHUT_RDWR);
                sock_release(sock);
                sock = NULL;
                isCreateSock = false;// test
            }
        }



        pr_info("tgame thread run\n");


    }
    return 0;
}

int ktg_core_init(void) {
    // 创建线程并启动
    thread = kthread_run(tgame_callback, NULL, "ktg");
    if (IS_ERR(thread)) {
        pr_info("Failed to create tgame thread\n");
        return PTR_ERR(thread);
    }
    return 0;
}

int ktg_core_exit(void) {
    if (thread)
        kthread_stop(thread);
    return 0;
}