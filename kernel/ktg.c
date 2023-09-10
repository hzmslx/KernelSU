#include "klog.h"

#include "linux/kernel.h"
#include "linux/module.h"
#include "linux/kthread.h"
#include "linux/delay.h"

static int
tgame_callback(void* unused)
{
    while(!kthread_should_stop()){
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