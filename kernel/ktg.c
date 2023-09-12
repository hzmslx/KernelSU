#include "klog.h"

#include "linux/kernel.h"
#include "linux/module.h"
#include "linux/sched/mm.h"
#include "linux/init.h"
#include "linux/kthread.h"
#include "linux/delay.h"
#include "linux/version.h"
#include "linux/tty.h"
#include "linux/mm.h"

#include "linux/errno.h"
#include "linux/types.h"

#include "linux/net.h"
#include "linux/inet.h"
#include "linux/socket.h"
#include "linux/in.h"

#include "asm/cpu.h"
#include "asm/io.h"
#include "asm/page.h"
#include "asm/pgtable.h"

// get pid
#include "linux/sched/signal.h"

static struct task_struct *thread = NULL;

// bool isCreateSock = false;

pid_t get_pid_by_name(const char *process_name) {
    struct task_struct *tasks;
    pid_t pid = -1;

    read_lock(&tasklist_lock);
    for_each_process(tasks) {
        char buf[TASK_COMM_LEN];
        get_task_comm(buf, tasks);
        pr_info("pid:%d name:%s\n", task_pid_nr(tasks), buf);
        if (strcmp(buf, process_name) == 0) {
            pid = task_pid_nr(tasks);
            break;
        }
    }
    read_unlock(&tasklist_lock);
    return pid;
}

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

#pragma pack (1)
struct Entity {
    short obj_id;
    char camp;
    float x;
    float y;
};

struct GameCorePacket {
    char PacketLen;
    int Pid;
    uintptr_t libGameCoreBase;
    uintptr_t libGameCoreBssBase;
    struct Entity LocalPlayer;
} GameCore;
#pragma pack ()

static struct task_struct *listen_thread = NULL;
static struct task_struct *loop_thread = NULL;
static struct socket *listen_socket = NULL;

bool isCreateSock = false;
bool isBindServer = false;
bool isListenSock = false;

int tcp_server_listen(void *unused) {

    while (!kthread_should_stop()) {
        if (isCreateSock == false) {
            int server_err = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP, &listen_socket);
            if (server_err < 0) {
                pr_warn("failed to create socket: %d\n", server_err);
                msleep(3000);
                continue;
            }
            isCreateSock = true;
        } else {
            if (isBindServer == false) {
                struct sockaddr_in server;
                server.sin_addr.s_addr = INADDR_ANY;
                server.sin_family = AF_INET;
                server.sin_port = htons(8181);

                int server_err = kernel_bind(listen_socket, (struct sockaddr *) &server, sizeof(server));
                if (server_err < 0) {
                    pr_warn("failed to bind server: %d\n", server_err);
                    msleep(3000);
                    continue;
                }
                isBindServer = true;
            } else {
                if (isListenSock == false) {
                    int server_err = kernel_listen(listen_socket, 5);
                    if (server_err < 0) {
                        pr_warn("failed to listen socket: %d\n", server_err);
                        msleep(3000);
                        continue;
                    }
                    isListenSock = true;
                } else {
                    while (true) {
                        struct socket *remote_socket = NULL;
                        int server_err = kernel_accept(listen_socket, &remote_socket, O_NONBLOCK);
                        if (server_err < 0) {
                            pr_warn("failed to accept socket: %d\n", server_err);
                            msleep(3000);
                            break;
                        } else {
                            struct sockaddr_storage client_addr;
                            int getnameErr = kernel_getsockname(remote_socket, (struct sockaddr *) &client_addr);
                            if (getnameErr < 0) {
                                pr_info("getnameErr: %d\n", getnameErr);
                                kernel_sock_shutdown(remote_socket, SHUT_RDWR);
                                sock_release(remote_socket);
                                continue;
                            }

                            if (client_addr.ss_family == AF_INET) {
                                struct sockaddr_in *ipv4 = (struct sockaddr_in *) &client_addr;
                                const uint8_t *ipv4_str = (uint8_t *) &(ipv4->sin_addr);
                                char ip_str[INET6_ADDRSTRLEN];
                                snprintf(ip_str, INET_ADDRSTRLEN, "%d.%d.%d.%d", ipv4_str[0], ipv4_str[1], ipv4_str[2],
                                         ipv4_str[3]);
                                pr_info("connect client ip: %s\n", ip_str);

                                char *send_buf = NULL;
                                send_buf = kmalloc(1024, GFP_KERNEL);
                                if (send_buf == NULL) {
                                    pr_info("send_buf kmalloc error!\n");
                                    kernel_sock_shutdown(remote_socket, SHUT_RDWR);
                                    sock_release(remote_socket);
                                    continue;
                                }
                                while (true) {
                                    struct kvec send_vec;
                                    struct msghdr send_msg;
                                    memset(send_buf, 'a', 1024);
                                    memset(&send_msg, 0, sizeof(send_msg));
                                    memset(&send_vec, 0, sizeof(send_vec));

                                    GameCore.PacketLen = sizeof(GameCore) - 1;
                                    GameCore.LocalPlayer.camp = 2;
                                    GameCore.LocalPlayer.x = 41.7f;
                                    GameCore.LocalPlayer.y = 41.7f;

                                    send_vec.iov_base = &GameCore;
                                    send_vec.iov_len = sizeof(GameCore);
                                    int send_err = kernel_sendmsg(remote_socket, &send_msg, &send_vec, 1,
                                                                  sizeof(GameCore));
                                    // kfree(send_buf);
                                    if (send_err < 0) {
                                        pr_info("kernel send msg error: %d\n", send_err);
                                        kernel_sock_shutdown(remote_socket, SHUT_RDWR);
                                        sock_release(remote_socket);
                                        break;
                                    }
                                    msleep(500);
                                }
                            } else {
                                kernel_sock_shutdown(remote_socket, SHUT_RDWR);
                                sock_release(remote_socket);
                            }
                        }
                    }
                }
            }
        }

    }
}

/*
phys_addr_t translate_linear_address(struct mm_struct* mm, uintptr_t va) {

    pgd_t *pgd;
    pmd_t *pmd;
    pte_t *pte;
    pud_t *pud;

    phys_addr_t page_addr;
    uintptr_t page_offset;

    pgd = pgd_offset(mm, va);
    if(pgd_none(*pgd) || pgd_bad(*pgd)) {
        return 0;
    }
    pud = pud_offset(pgd,va);
    if(pud_none(*pud) || pud_bad(*pud)) {
        return 0;
    }
    pmd = pmd_offset(pud,va);
    if(pmd_none(*pmd)) {
        return 0;
    }
    pte = pte_offset_kernel(pmd,va);
    if(pte_none(*pte)) {
        return 0;
    }
    if(!pte_present(*pte)) {
        return 0;
    }
    //页物理地址
    page_addr = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT);
    //页内偏移
    page_offset = va & (PAGE_SIZE-1);

    return page_addr + page_offset;
}

#ifndef ARCH_HAS_VALID_PHYS_ADDR_RANGE
static inline int valid_phys_addr_range(phys_addr_t addr, size_t count) {
    return addr + count <= __pa(high_memory);
}
#endif

bool read_proc_mem(
        pid_t pid,
        uintptr_t addr,
        void *buffer,
        size_t size) {

    struct task_struct *task;
    struct mm_struct *mm;
    struct pid *pid_struct;
    phys_addr_t pa;

    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        return false;
    }
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        return false;
    }
    mm = get_task_mm(task);
    if (!mm) {
        return false;
    }
    mmput(mm);
    pa = translate_linear_address(mm, addr);
    if (!pa) {
        return false;
    }
}
*/

#define ARC_PATH_MAX 256

uintptr_t get_module_base(pid_t pid, char *name) {
    struct pid *pid_struct;
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    uintptr_t base = 0;

    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        return 0;
    }
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        put_pid(pid_struct);
        return 0;
    }
    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        put_pid(pid_struct);
        return 0;
    }
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        char buf[ARC_PATH_MAX];
        char *path_nm = "";

        if (vma->vm_file) {
            path_nm = file_path(vma->vm_file, buf, ARC_PATH_MAX - 1);
            if (!strcmp(kbasename(path_nm), name)) {
                base = vma->vm_start;
                break;
            }
        }
    }
    mmput(mm);
    put_task_struct(task);
    put_pid(pid_struct);
    return base;
}

uintptr_t get_module_bss_base(pid_t pid, char *name) {
    struct pid *pid_struct;
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    uintptr_t bss_base = 0;

    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        return 0;
    }
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        put_pid(pid_struct);
        return 0;
    }
    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        put_pid(pid_struct);
        return 0;
    }
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        char buf[ARC_PATH_MAX];
        char *path_nm = "";

        if (vma->vm_file) {
            path_nm = file_path(vma->vm_file, buf, ARC_PATH_MAX - 1);
            if (!strcmp(kbasename(path_nm), name)) {
                Elf64_Ehdr *ehdr = (Elf64_Ehdr *)vma->vm_start;
                Elf64_Shdr *shdr = (Elf64_Shdr *)(vma->vm_start + ehdr->e_shoff);

                // 遍历节区头表，查找BSS段
                for (int i = 0; i < ehdr->e_shnum; i++) {
                    if (shdr[i].sh_type == SHT_NOBITS) {
                        bss_base = vma->vm_start + shdr[i].sh_offset;
                        break;
                    }
                }

                break;
            }
        }
    }
    mmput(mm);
    put_task_struct(task);
    put_pid(pid_struct);
    return bss_base;
}

int game_loop_callback(void *unused) {
    while (!kthread_should_stop()) {
        pid_t tgame = get_pid_by_name("com.tencent.tmgp.sgame");
        if (tgame != -1) {
            GameCore.Pid = tgame;
            GameCore.libGameCoreBase = get_module_base(tgame, "libGameCore.so");
            GameCore.libGameCoreBssBase = get_module_bss_base(tgame, "libGameCore.so");
            pr_info("tgame_pid: %d\n", GameCore.Pid);
            pr_info("libGameCoreBase: %lx\n", GameCore.libGameCoreBase);
            pr_info("libGameCoreBssBase: %lx\n", GameCore.libGameCoreBase);
        }

        msleep(5000);
    }
}

int tcp_server_start(void) {

    listen_thread = kthread_run((void *) tcp_server_listen, NULL, "tcp-server");
    if (IS_ERR(listen_thread)) {
        pr_info("failed to create listen thread\n");
        return PTR_ERR(listen_thread);
    }

    loop_thread = kthread_run((void *) game_loop_callback, NULL, "loop");
    if (IS_ERR(loop_thread)) {
        pr_info("failed to create loop thread\n");
        return PTR_ERR(loop_thread);
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