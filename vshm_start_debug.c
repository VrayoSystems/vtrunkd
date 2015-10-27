#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <semaphore.h>
#include <sys/shm.h>
#include <errno.h>

#include "vtun.h"

#define SHM_TUN_KEY 567888

int main() {
    int key_conn_info = SHM_TUN_KEY, shmid;
    struct conn_info *shm_conn_info = NULL;
    if ((shmid = shmget(key_conn_info, sizeof(struct conn_info), 0666)) < 0) {
        printf("Netlink_server_init Can not attach SHM supervisor buffer of size %lu", sizeof(struct conn_info));
        return 0;
    }

    if ((shm_conn_info = (struct conn_info *)shmat(shmid, NULL, 0)) == (struct conn_info *) - 1) {
        printf("Main shm not ready yet (netlink server)");
        return 0;
    }
    shm_conn_info->packet_debug_enabled = 1;

    return 0;
}
