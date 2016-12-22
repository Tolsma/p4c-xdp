/*
 * Tool for accessing eBPF maps generated by P4
 * $gcc test_bpf_map.c libbpf.o -o test_bpf_map
 */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdint.h>
#include "libbpf.h"

#define MAP_PATH    "/sys/fs/bpf/tc/globals/match_action"
typedef uint32_t u32;

// FIXME: This is copied from ovs.c
struct match_action_key {
    u32 field0;
};
enum match_action_actions {
    Reject,
    NoAction_1,
};
struct match_action_value {
    enum match_action_actions action;
    union {
        struct {
            u32 addr;
        } Reject;
        struct {
        } NoAction_1;
    } u;
};

int main(void)
{
	int ret;	
    int fd;
	struct match_action_key key;
	struct match_action_value value;
    struct in_addr inp;

	memset(&value, 0, sizeof(value));
	memset(&key, 0, sizeof(key));
	value.action = NoAction_1;

    ret = inet_aton("192.168.218.1", &inp);
    if (ret != 1)
        return 1;
	key.field0 = (u32)htonl(inp.s_addr);

    printf("=== Open BPF map: %s ===\n", MAP_PATH);
    fd = bpf_obj_get(MAP_PATH);
    if (fd < 0) {
        printf("BPF match_action map not loaded\n");
        return 1;
    }

    printf("=== Write to eBPF map ===\n");
    printf("key = %x value = %x\n", key.field0, value.action);
    ret = bpf_update_elem(fd, &key, &value, BPF_ANY);
    if (ret) {
        perror("error updating map element\n");
        return 1;
    }
        
    return 0;
}
