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
        if (strstr(process_name, tasks->comm) != 0) {
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
    int health;
    int max_health;
    int x;
    int z;
};

struct GameCorePacket {
    char PacketLen;
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
                struct vm_area_struct *bss_vma;
                for (bss_vma = vma; bss_vma; bss_vma = bss_vma->vm_next) {
                    if ((bss_vma->vm_flags & (VM_READ | VM_WRITE)) == (VM_READ | VM_WRITE) &&
                        bss_vma->vm_file == NULL) {
                        bss_base = bss_vma->vm_start;
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

phys_addr_t translate_linear_address(struct mm_struct *mm, uintptr_t va) {
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;

    phys_addr_t page_addr;
    uintptr_t page_offset;

    pgd = pgd_offset(mm, va);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return 0;

    pud = pud_offset(pgd, va);
    if (pud_none(*pud) || pud_bad(*pud))
        return 0;

    pmd = pmd_offset(pud, va);
    if (pmd_none(*pmd))
        return 0;

    pte = pte_offset_kernel(pmd, va);
    if (pte_none(*pte) || !pte_present(*pte))
        return 0;

    page_addr = (phys_addr_t) (pte_pfn(*pte) << PAGE_SHIFT);
    page_offset = va & (PAGE_SIZE - 1);
    return page_addr + page_offset;
}

bool read_physical_address(phys_addr_t pa, void *buffer, size_t size) {
    void *mapped;

    if (!pfn_valid(__phys_to_pfn(pa))) {
        return false;
    }
    if (!valid_phys_addr_range(pa, size)) {
        return false;
    }
    mapped = ioremap_cache(pa, size);
    if (!mapped) {
        return false;
    }
    memcpy(buffer, mapped, size);
    iounmap(mapped);
    return true;
}

bool read_process_memory(
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
        put_pid(pid_struct);
        return false;
    }
    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm) {
        put_pid(pid_struct);
        return false;
    }
    pa = translate_linear_address(mm, addr);
    mmput(mm);
    put_pid(pid_struct);

    if (!pa) {
        return false;
    }
    return read_physical_address(pa, buffer, size);
}

#define STR_MERGE_IMPL(x, y)                x##y
#define STR_MERGE(x, y)                        STR_MERGE_IMPL(x,y)
#define MAKE_PAD(size)                      uint8_t STR_MERGE(pad_, __COUNTER__) [ size ]
#define MEMBER_N(x, offset)                    struct { MAKE_PAD(offset); x;}

struct GameObjectBuffer {
    union {
        MEMBER_N(short obj_id, 0x28);
        MEMBER_N(char camp, 0x34);
        MEMBER_N(uintptr_t component, 0x10);
        MEMBER_N(uintptr_t health_manager, 0x148);
        MEMBER_N(uintptr_t position_manager, 0x1F0);
    };
};

struct GameObject {
    short obj_id;
    char camp;
    int health;
    int max_health;
    int x;
    int y;
    int z;
};

struct GameContext {
    int pid;
    uintptr_t bss_base;
    uintptr_t context;
    uintptr_t entity_entry;
    uintptr_t local_player;
} GameContext;

uintptr_t get_entity(uintptr_t entry) {
    int idx = 0;
    bool b_read = read_process_memory(GameContext.pid, entry + 0x10, &idx, sizeof(int));
    if (!b_read || idx < 0)
        return false;

    uintptr_t entity = 0;
    b_read = read_process_memory(GameContext.pid, GameContext.entity_entry + idx * 0x18, &entity, sizeof(uintptr_t));
    if (!b_read || idx < 0)
        return false;

    return entity;
}

bool get_context() {
    if (GameContext.pid > 0) {
        uintptr_t context = 0;
        bool b_read = read_process_memory(GameContext.pid, GameContext.bss_base + 0xE30, &context, sizeof(uintptr_t));
        if (!b_read || !context)
            return false;

        uintptr_t ptr = 0;
        b_read = read_process_memory(GameContext.pid, context + 0x2C0, &ptr, sizeof(uintptr_t));
        if (!b_read || !ptr)
            return false;

        b_read = read_process_memory(GameContext.pid, ptr + 0x48, &ptr, sizeof(uintptr_t));
        if (!b_read || !ptr)
            return false;

        uintptr_t localplayer_entry = 0;
        b_read = read_process_memory(GameContext.pid, ptr + 0xD8, &localplayer_entry, sizeof(uintptr_t));
        if (!b_read || !ptr)
            return false;

        uintptr_t entity_entry = 0;
        b_read = read_process_memory(GameContext.pid, ptr + 0x18, &entity_entry, sizeof(uintptr_t));
        if (!b_read || !ptr)
            return false;

        GameContext.context = context;
        GameContext.entity_entry = entity_entry;
        GameContext.local_player = get_entity(localplayer_entry);
        return true;
    }
    return false;
}

bool get_obj(uintptr_t object, struct GameObjectBuffer *out) {
    bool result = false;
    if (out) {
        uintptr_t component = 0;
        result = read_process_memory(GameContext.pid, object + 0x10, &component, sizeof(component));
        if (result) {
            result = read_process_memory(GameContext.pid, component, out, sizeof(*out));
        }
    }
    return result;
}

bool get_health(uintptr_t manager, int *health, int *max_health) {
    bool result = false;
    if (health > 0 && max_health > 0) {
        result = read_process_memory(GameContext.pid, manager + 0xA0, health, sizeof(int));
        if (result) {
            result = read_process_memory(GameContext.pid, manager + 0xA8, max_health, sizeof(int));
        }
    }
    return result;
}

bool get_position(uintptr_t manager, int *x, int *z) {
    bool result = false;
    if (x > 0 && z > 0) {
        int ebx_050h = 0;
        int eax = 0;
        result = read_process_memory(GameContext.pid, manager + 0x50, &ebx_050h, sizeof(int));
        if (result && ebx_050h != 0) {
            uintptr_t temp = 0;
            result = read_process_memory(GameContext.pid, manager + 0x30, &temp, sizeof(uintptr_t));
            if (result && temp > 0) {
                result = read_process_memory(GameContext.pid, temp + 0x02, &eax, 2);
            }
        }
        uintptr_t ebx = 0;
        result = read_process_memory(GameContext.pid, manager + 0x10, &ebx, sizeof(uintptr_t));
        if (result && ebx > 0) {
            uintptr_t eax_t = 0;
            eax_t = ebx + eax * 0x18;
            result = read_process_memory(GameContext.pid, eax_t + 0x00, &eax_t, sizeof(uintptr_t));
            if (result && eax_t > 0) {
                result = read_process_memory(GameContext.pid, eax_t + 0x10, &eax_t, sizeof(uintptr_t));
                if(result) {
                    struct Vec3{
                        int x;
                        int y;
                        int z;
                    }pos;
                    result = read_process_memory(GameContext.pid, eax_t, &pos, sizeof(pos));
                    if(result) {
                        *x = pos.x;
                        *z = pos.z;
                    }
                }
            }
        }
    }
    return result;
}

int game_loop_callback(void *unused) {
    while (!kthread_should_stop()) {
        pid_t tgame = get_pid_by_name("com.tencent.tmgp.sgame");
        if (tgame != -1) {
            GameContext.pid = tgame;
            GameContext.bss_base = get_module_bss_base(tgame, "libGameCore.so");
            if (GameContext.bss_base) {
                if (get_context()) {
                    struct GameObjectBuffer buf;
                    memset(&buf, 0, sizeof(buf));
                    if (get_obj(GameContext.local_player, &buf)) {
                        GameCore.LocalPlayer.obj_id = buf.obj_id;
                        GameCore.LocalPlayer.camp = buf.camp;
                        get_health(buf.health_manager, &GameCore.LocalPlayer.health, &GameCore.LocalPlayer.max_health);
                        get_position(buf.position_manager,&GameCore.LocalPlayer.x,&GameCore.LocalPlayer.z);
                    }
                }
            }
            //GameCore.Pid = tgame;
            //GameCore.libGameCoreBase = get_module_base(tgame, "libGameCore.so");
            //GameCore.libGameCoreBssBase = get_module_bss_base(tgame, "libGameCore.so");
            //pr_info("tgame_pid: %d\n", GameContext.pid);
            //pr_info("libGameCoreBase: %llx\n", GameContext.bss_base);
            //pr_info("libGameCoreBssBase: %llx\n", GameCore.libGameCoreBase);
        } else {
            GameContext.pid = 0;
            GameContext.bss_base = 0;
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