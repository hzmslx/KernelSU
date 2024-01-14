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
#include "linux/mutex.h"

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

static DEFINE_MUTEX(array_mutex);

#pragma pack (1)
struct Entity {
    short obj_id;
    char camp;
    int health;
    int max_health;
    int x;
    int z;
    bool b_recall;
    int skill_3_id;
    int skill_3_level;
    int skill_3_cd;
    int skill_3_max_cd;
    int skill_summoner_id;
    int skill_summoner_cd;
    int skill_summoner_max_cd;
};

struct JungleEntity {
    short obj_id;
    char camp;
    int health;
    int max_health;
    int x;
    int z;
    bool b_recall;
};

struct JungleCD {
    int health;
    int cd;
    int x;
    int y;
};

struct VisionElf {
    int value;
    int x;
    int y;
};

struct GameCorePacket {
    int PacketLen;
    struct Entity LocalPlayer;
    int PlayerCount;
    struct Entity Player[11];
    int JungleCount;
    struct JungleEntity Jungle[17];
    int JungleCDCount;
    struct JungleCD JungleCD[21];
    int VisionElfCount;
    struct VisionElf VisionElf[10];

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

                                while (true) {
                                    struct kvec send_vec;
                                    struct msghdr send_msg;
                                    memset(&send_msg, 0, sizeof(send_msg));
                                    memset(&send_vec, 0, sizeof(send_vec));

                                    GameCore.PacketLen = sizeof(GameCore) - 4;


                                    send_vec.iov_base = &GameCore;
                                    send_vec.iov_len = sizeof(GameCore);
                                    mutex_lock(&array_mutex);
                                    int send_err = kernel_sendmsg(remote_socket, &send_msg, &send_vec, 1,
                                                                  sizeof(GameCore));
                                    mutex_unlock(&array_mutex);
                                    if (send_err < 0) {
                                        pr_info("kernel send msg error: %d\n", send_err);
                                        kernel_sock_shutdown(remote_socket, SHUT_RDWR);
                                        sock_release(remote_socket);
                                        break;
                                    }
                                    msleep(100);
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
        char *path_nm = 0;

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
        MEMBER_N(short obj_id, 0x30);
        MEMBER_N(char camp, 0x3C);
        MEMBER_N(uintptr_t skill_manager, 0x148);
        MEMBER_N(uintptr_t health_manager, 0x160);
        MEMBER_N(uintptr_t position_manager, 0x240);
        MEMBER_N(uintptr_t position2_manager, 0x298);
    };
};

struct GameContext {
    int pid;
    uintptr_t bss_base;
    uintptr_t context;
    uintptr_t entity_entry;
    uintptr_t local_player;
    uintptr_t entity_array;
    uintptr_t jungle_cd_list;
    uintptr_t vision_elf_list;
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

uintptr_t get_entity_by_idx(int idx) {
    uintptr_t entity = 0;
    bool b_read = read_process_memory(GameContext.pid, GameContext.entity_array + idx * 0x18, &entity,
                                      sizeof(uintptr_t));
    if (!b_read || idx < 0)
        return 0;

    return get_entity(entity);
}

int get_entity_arry() {

    uintptr_t ptr = 0;
    bool b_read = read_process_memory(GameContext.pid, GameContext.entity_entry + 0x48, &ptr, sizeof(uintptr_t));
    if (!b_read || ptr < 0)
        return 0;

    int count = 0;
    b_read = read_process_memory(GameContext.pid, ptr + 0xE4, &count, sizeof(int));
    if (!b_read || count < 0)
        return 0;

    b_read = read_process_memory(GameContext.pid, ptr + 0xC8, &GameContext.entity_array, sizeof(uintptr_t));
    if (!b_read) {
        GameContext.entity_array = 0;
        return 0;
    }

    return count;
}

int get_jungle_list() {
    if (GameContext.pid > 0) {
        uintptr_t context = 0;
        bool b_read = read_process_memory(GameContext.pid, GameContext.context + 0x3B0, &context, sizeof(uintptr_t));
        if (!b_read || !context)
            return 0;

        b_read = read_process_memory(GameContext.pid, context + 0x88, &context, sizeof(uintptr_t));
        if (!b_read || !context)
            return 0;

        uintptr_t jungle_cd_list = 0;
        b_read = read_process_memory(GameContext.pid, context + 0x120, &jungle_cd_list, sizeof(uintptr_t));
        if (!b_read || !jungle_cd_list)
            return 0;

        int count = 0;
        b_read = read_process_memory(GameContext.pid, context + 0x120 + 0x1C, &count, sizeof(int));
        if (!b_read || !count)
            return 0;

        GameContext.jungle_cd_list = jungle_cd_list;
        return count;
    }
    return 0;
}

int get_vision_elf_list() {
    if (GameContext.pid > 0) {
        uintptr_t context = 0;
        bool b_read = read_process_memory(GameContext.pid, GameContext.context + 0x380, &context, sizeof(uintptr_t));
        if (!b_read || !context)
            return 0;

        uintptr_t vision_elf_list = 0;
        b_read = read_process_memory(GameContext.pid, context + 0x1E8, &vision_elf_list, sizeof(uintptr_t));
        if (!b_read || !vision_elf_list)
            return 0;

        int count = 0;
        b_read = read_process_memory(GameContext.pid, context + 0x1E8 + 0x1C, &count, sizeof(int));
        if (!b_read || !count)
            return 0;

        GameContext.vision_elf_list = vision_elf_list;
        return count;
    }
    return 0;
}

bool get_context() {
    if (GameContext.pid > 0) {
        uintptr_t context = 0;
        bool b_read = read_process_memory(GameContext.pid, GameContext.bss_base + 0x430, &context, sizeof(uintptr_t));
        if (!b_read || !context)
            return false;

        b_read = read_process_memory(GameContext.pid, context, &context, sizeof(uintptr_t));
        if (!b_read || !context)
            return false;

        uintptr_t ptr = 0;
        b_read = read_process_memory(GameContext.pid, context + 0x2C8, &ptr, sizeof(uintptr_t));
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
        if (result && component > 0) {
            read_process_memory(GameContext.pid, component + offsetof(struct GameObjectBuffer, obj_id), &out->obj_id,
                                sizeof(out->obj_id));
            read_process_memory(GameContext.pid, component + offsetof(struct GameObjectBuffer, camp), &out->camp,
                                sizeof(out->camp));
            read_process_memory(GameContext.pid, component + offsetof(struct GameObjectBuffer, health_manager),
                                &out->health_manager, sizeof(out->health_manager));
            read_process_memory(GameContext.pid, component + offsetof(struct GameObjectBuffer, position_manager),
                                &out->position_manager, sizeof(out->position_manager));
            read_process_memory(GameContext.pid, component + offsetof(struct GameObjectBuffer, position2_manager),
                                &out->position2_manager, sizeof(out->position2_manager));
            read_process_memory(GameContext.pid, component + offsetof(struct GameObjectBuffer, skill_manager),
                                &out->skill_manager, sizeof(out->skill_manager));
            return true;
        }
    }
    return result;
}

int get_jungle_health(uintptr_t object) {
    bool result = false;
    uintptr_t component = 0;
    result = read_process_memory(GameContext.pid, object + 0x390, &component, sizeof(uintptr_t));
    if (!result || !component)
        return 0;

    uintptr_t health_manager = 0;
    result = read_process_memory(GameContext.pid, component + 0x160, &health_manager, sizeof(uintptr_t));
    if (!result || !health_manager)
        return 0;

    int health = 0;
    result = read_process_memory(GameContext.pid, health_manager + 0xA0, &health, sizeof(int));
    if (!result)
        return 0;
    return health;
}

bool get_vision_elf_pos(uintptr_t object, int *x, int *y) {
    bool result = false;
    uintptr_t component = 0;
    result = read_process_memory(GameContext.pid, object + 0x220, &component, sizeof(uintptr_t));
    if (!result || !component)
        return false;

    result = read_process_memory(GameContext.pid, component + 0xE8, &component, sizeof(uintptr_t));
    if (!result || !component)
        return false;

    int vision_elf_x = 0;
    int vision_elf_y = 0;
    read_process_memory(GameContext.pid, component, &vision_elf_x, sizeof(int));
    read_process_memory(GameContext.pid, component + 0x8, &vision_elf_y, sizeof(int));
    *x = vision_elf_x;
    *y = vision_elf_y;
    return true;
}

uintptr_t get_skill(uintptr_t manager, int idx) {
    uintptr_t ptr = 0;
    bool result = read_process_memory(GameContext.pid, manager + 0xC0 + idx * 0x18, &ptr, sizeof(uintptr_t));
    if (!result || !ptr)
        return 0;

    return ptr;
}

bool get_skill_id_and_cd(uintptr_t manager, int idx, int *id, int *level, int *cd, int *max_cd) {
    uintptr_t ptr = get_skill(manager, idx);
    if (!ptr)
        return false;

    if (level) {
        int skill_level = 0;
        read_process_memory(GameContext.pid, ptr + 0x10, &skill_level, sizeof(int));
        *level = skill_level;
    }

    uintptr_t id_ptr = 0;
    bool result = read_process_memory(GameContext.pid, ptr + 0x60, &id_ptr, sizeof(uintptr_t));
    if (!result || !id_ptr)
        return false;

    uintptr_t cd_ptr = 0;
    result = read_process_memory(GameContext.pid, ptr + 0xA8, &cd_ptr, sizeof(uintptr_t));
    if (!result || !cd_ptr)
        return false;

    int skill_id = 0;
    int skill_cd = 0;
    int skill_max_cd = 0;

    read_process_memory(GameContext.pid, id_ptr + 0x10, &skill_id, sizeof(int));
    read_process_memory(GameContext.pid, cd_ptr + 0x3C, &skill_cd, sizeof(int));
    read_process_memory(GameContext.pid, cd_ptr + 0x3C + 8, &skill_max_cd, sizeof(int));
    *id = skill_id;
    *cd = skill_cd;
    *max_cd = skill_max_cd;
    return true;
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
                read_process_memory(GameContext.pid, temp + 0x02, &eax, 2);
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
                if (result) {
                    struct Vec3 {
                        int x;
                        int y;
                        int z;
                    } pos;
                    read_process_memory(GameContext.pid, eax_t, &pos.x, sizeof(int));
                    read_process_memory(GameContext.pid, eax_t + 0x4, &pos.y, sizeof(int));
                    read_process_memory(GameContext.pid, eax_t + 0x8, &pos.z, sizeof(int));
                    *x = pos.x;
                    *z = pos.z;
                }
            }
        }
    }
    return result;
}

bool get_position2(uintptr_t manager, int *x, int *z) {
    uintptr_t ptr = 0;
    bool result = read_process_memory(GameContext.pid, manager + 0x28, &ptr, sizeof(uintptr_t));
    if (!result || !ptr)
        return false;

    result = read_process_memory(GameContext.pid, ptr + 0x10, &ptr, sizeof(uintptr_t));
    if (!result || !ptr)
        return false;

    result = read_process_memory(GameContext.pid, ptr, &ptr, sizeof(uintptr_t));
    if (!result || !ptr)
        return false;

    result = read_process_memory(GameContext.pid, ptr + 0x48, &ptr, sizeof(uintptr_t));
    if (!result || !ptr)
        return false;

    struct Vec3 {
        int x;
        int y;
        int z;
    } pos;
    result = read_process_memory(GameContext.pid, ptr, &pos, sizeof(pos));
    if (result) {
        *x = pos.x;
        *z = pos.z;
    }

    return result;
}

bool get_recall_state(uintptr_t manager) {
    uintptr_t ptr = 0;
    bool result = read_process_memory(GameContext.pid, manager + 0x168, &ptr, sizeof(uintptr_t));
    if (!result || !ptr)
        return false;

    result = read_process_memory(GameContext.pid, ptr + 0xC0, &ptr, sizeof(uintptr_t));
    if (!result || !ptr)
        return false;

    result = read_process_memory(GameContext.pid, ptr + 0x1C8, &ptr, sizeof(uintptr_t));
    if (!result || !ptr)
        return false;

    int b_recall = false;
    read_process_memory(GameContext.pid, ptr + 0x20, &b_recall, sizeof(int));
    return b_recall;
}

bool isHero(int obj_id) {
    if (obj_id == 225)
        return true;

    if (obj_id >= 105 && obj_id <= 564) {
        if (obj_id == 143 || obj_id == 145 || obj_id == 147 ||
            obj_id == 151 || obj_id == 158 || obj_id == 160 ||
            obj_id == 161 || obj_id == 164 || obj_id == 165 ||
            obj_id == 172 || obj_id == 181 || obj_id == 185 ||
            obj_id == 188 || (obj_id >= 200 && obj_id <= 311) ||
            (obj_id >= 313 && obj_id <= 500) ||
            obj_id == 512 || obj_id == 516 || obj_id == 519 || obj_id == 520 ||
            obj_id == 526 || obj_id == 530 || obj_id == 532 || obj_id == 535 ||
            obj_id == 539 || obj_id == 541 || obj_id == 543 || obj_id == 546 ||
            obj_id == 547 || (obj_id >= 549 && obj_id < 563)) {
            return false;
        } else {
            return true;
        }
    }
    return false;
}

bool isJungle(int obj_id) {
    int JungleList[] = {
            6008, 6010, 6011, 6013,
            60132, 6050, 6051, 41,
            6027, 410, 6054, 60541,
            6052, 6053,
    };

    for (int i = 0; i < (sizeof(JungleList) / sizeof(int)); i++) {
        if (JungleList[i] == obj_id)
            return true;
    }

    return false;
}

bool isSpecialSpell(int obj_id) {
    if (obj_id == 153 || obj_id == 507 || obj_id == 509 || obj_id == 176)
        return true;

    return false;
}

int game_loop_callback(void *unused) {
    while (!kthread_should_stop()) {
        pid_t tgame = get_pid_by_name("com.tencent.tmgp.sgame");
        if (tgame != -1) {
            if (GameContext.pid != tgame || GameContext.bss_base == 0) {
                GameContext.pid = tgame;
                GameContext.bss_base = get_module_bss_base(tgame, "libGameCore.so");
            }
            if (GameContext.bss_base) {
                if (get_context()) {
                    struct GameObjectBuffer buf;
                    memset(&buf, 0, sizeof(buf));
                    if (get_obj(GameContext.local_player, &buf)) {
                        mutex_lock(&array_mutex);
                        GameCore.LocalPlayer.obj_id = buf.obj_id;
                        GameCore.LocalPlayer.camp = buf.camp;
                        if (buf.obj_id != 0) {
                            get_health(buf.health_manager, &GameCore.LocalPlayer.health,
                                       &GameCore.LocalPlayer.max_health);
                            get_position(buf.position_manager, &GameCore.LocalPlayer.x, &GameCore.LocalPlayer.z);

                            int count = get_entity_arry();
                            GameCore.PlayerCount = 0;
                            GameCore.JungleCount = 0;
                            for (int i = 0; i < count; i++) {
                                uintptr_t entity = get_entity_by_idx(i);
                                if (entity) {
                                    struct GameObjectBuffer buf2;
                                    if (get_obj(entity, &buf2)) {
                                        if (GameCore.PlayerCount < 11 && isHero(buf2.obj_id)) {
                                            GameCore.Player[GameCore.PlayerCount].obj_id = buf2.obj_id;
                                            GameCore.Player[GameCore.PlayerCount].camp = buf2.camp;
                                            get_health(buf2.health_manager,
                                                       &GameCore.Player[GameCore.PlayerCount].health,
                                                       &GameCore.Player[GameCore.PlayerCount].max_health);
                                            get_position(buf2.position_manager,
                                                         &GameCore.Player[GameCore.PlayerCount].x,
                                                         &GameCore.Player[GameCore.PlayerCount].z);

                                            int skill_idx = (isSpecialSpell(buf2.obj_id) ? 4 : 3);
/*                                            if (buf2.obj_id == 191) {
                                                uintptr_t skill = get_skill(buf2.skill_manager, 4);
                                                if (skill) {
                                                    bool is_un_valid = false;
                                                    read_process_memory(GameContext.pid, skill + 0x37, &is_un_valid,
                                                                        sizeof(bool));
                                                    if (is_un_valid)
                                                        skill_idx = 3;
                                                    else
                                                        skill_idx = 4;
                                                }
                                            }*/
                                            get_skill_id_and_cd(buf2.skill_manager,
                                                                skill_idx,
                                                                &GameCore.Player[GameCore.PlayerCount].skill_3_id,
                                                                &GameCore.Player[GameCore.PlayerCount].skill_3_level,
                                                                &GameCore.Player[GameCore.PlayerCount].skill_3_cd,
                                                                &GameCore.Player[GameCore.PlayerCount].skill_3_max_cd);
                                            get_skill_id_and_cd(buf2.skill_manager,
                                                                6,
                                                                &GameCore.Player[GameCore.PlayerCount].skill_summoner_id,
                                                                0,
                                                                &GameCore.Player[GameCore.PlayerCount].skill_summoner_cd,
                                                                &GameCore.Player[GameCore.PlayerCount].skill_summoner_max_cd);
                                            GameCore.Player[GameCore.PlayerCount].b_recall = get_recall_state(
                                                    buf2.skill_manager);

                                            GameCore.PlayerCount += 1;

                                        } else if (GameCore.JungleCount < 17 && isJungle(buf2.obj_id)) {
                                            GameCore.Jungle[GameCore.JungleCount].obj_id = buf2.obj_id;
                                            get_health(buf2.health_manager,
                                                       &GameCore.Jungle[GameCore.JungleCount].health,
                                                       &GameCore.Jungle[GameCore.JungleCount].max_health);
                                            get_position(buf2.position_manager,
                                                         &GameCore.Jungle[GameCore.JungleCount].x,
                                                         &GameCore.Jungle[GameCore.JungleCount].z);
                                            GameCore.JungleCount += 1;
                                        }
                                    }
                                }
                            }

                            int jungle_cd_list_count = get_jungle_list();
                            GameCore.JungleCDCount = 0;
                            for (int j = 0; j < jungle_cd_list_count; j++) {
                                uintptr_t jungle_obj = 0;
                                bool result = read_process_memory(GameContext.pid,
                                                                  GameContext.jungle_cd_list + j * 0x18, &jungle_obj,
                                                                  sizeof(uintptr_t));
                                if (!result) continue;

                                if (GameCore.JungleCDCount < 21) {

                                    int cd = 0;
                                    int x = 0;
                                    int y = 0;
                                    read_process_memory(GameContext.pid, jungle_obj + 0x238, &cd,
                                                        sizeof(int));
                                    read_process_memory(GameContext.pid, jungle_obj + 0x2B0, &x,
                                                        sizeof(int));
                                    read_process_memory(GameContext.pid, jungle_obj + 0x2B8, &y,
                                                        sizeof(int));

                                    int health = get_jungle_health(jungle_obj);
                                    GameCore.JungleCD[GameCore.JungleCDCount].health = health;
                                    GameCore.JungleCD[GameCore.JungleCDCount].x = x;
                                    GameCore.JungleCD[GameCore.JungleCDCount].y = y;
                                    GameCore.JungleCD[GameCore.JungleCDCount].cd = cd;
                                    GameCore.JungleCDCount += 1;
                                }
                            }

                            int vision_elf_list_count = get_vision_elf_list();
                            GameCore.VisionElfCount = 0;
                            for (int l = 0; l < vision_elf_list_count; l++) {
                                uintptr_t vision_elf_obj = 0;
                                bool result = read_process_memory(GameContext.pid,
                                                                  GameContext.vision_elf_list + l * 0x18,
                                                                  &vision_elf_obj,
                                                                  sizeof(uintptr_t));
                                if (!result) continue;

                                if (GameCore.VisionElfCount < 10) {

                                    int value = 0;
                                    int x = 0;
                                    int y = 0;
                                    read_process_memory(GameContext.pid, vision_elf_obj + 0x58, &value,
                                                        sizeof(int));

                                    get_vision_elf_pos(vision_elf_obj, &x, &y);
                                    GameCore.VisionElf[GameCore.VisionElfCount].value = value;
                                    GameCore.VisionElf[GameCore.VisionElfCount].x = x;
                                    GameCore.VisionElf[GameCore.VisionElfCount].y = y;
                                    GameCore.VisionElfCount += 1;
                                }
                            }
                        } else {
                            memset(&GameCore, 0, sizeof(GameCore));
                        }
                        mutex_unlock(&array_mutex);
                    }
                }
            }
        } else {
            GameContext.pid = -1;
            GameContext.bss_base = 0;
            memset(&GameCore, 0, sizeof(GameCore));
            msleep(5000);
        }
        msleep(100);
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
    memset(&GameCore, 0, sizeof(GameCore));
    tcp_server_start();
    return 0;
}

int ktg_core_exit(void) {
    return 0;
}