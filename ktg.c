#include "linux/kernel.h"
#include "linux/module.h"
#include "linux/kthread.h"
#include "linux/delay.h"

#include "klog.h"

static int
tgame_callback(void* unused)
{
    while(!kthread_should_stop()){
        pr_info("tgame thread run\n");

        msleep(3000);
    }
    return 0;
}

int ktg_core_init()
{
    // 创建线程并启动
    struct task_struct *thread = kthread_run(tgame_callback, NULL, "ktg");
    if (IS_ERR(thread)) {
        pr_info("Failed to create tgame thread\n");
        return PTR_ERR(thread);
    }

    return 0
}