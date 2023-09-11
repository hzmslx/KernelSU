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

static int
tgame_callback(void* unused)
{
    struct socket *sock;
    struct sockadrr_in addr;
    
    int ret = sock_create_kern(&init_addr, AF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
    if(ret < 0) {
        pr_warn("failed to create socket: %d\n", ret);
        return ret;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = in_aton("127.0.0.1");
    addr.sin_port = htons(8080);

    while(!kthread_should_stop()) {

        ret = sock->ops->connect(sock, (struct sockaddr *)&addr, sizeof(addr), 0);
        if(ret < 0) {
            pr_warn("failed to connect: %d\n", ret);
        }
        else {
            pr_info("connect success!\n");
            sock->ops->shutdown(sock, SHUT_RDWR);
        }

        pr_info("tgame thread run\n");

        msleep(3000);
    }
    return 0;
}

struct task_struct * thread;

int ktg_core_init(void)
{
    // 创建线程并启动
    thread = kthread_run(tgame_callback, NULL, "ktg");
    if (IS_ERR(thread)) {
        pr_info("Failed to create tgame thread\n");
        return PTR_ERR(thread);
    }
    return 0;
}

int ktg_core_exit(void)
{
    if(thread)
        kthread_stop(thread);
    return 0;
}