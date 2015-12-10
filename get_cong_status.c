#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <semaphore.h>
#include <sys/shm.h>
#include <errno.h>

#include "vtun.h"

int main(int argc, char *argv[])
{
    if(argc < 2) {
        printf("Please provide SHM_TUN_KEY\n");
        exit(1);
    }
    int key_conn_info = atoi(argv[1]), shmid;
    struct conn_info *shm_conn_info = NULL;
    if ((shmid = shmget(key_conn_info, sizeof(struct conn_info), 0666)) < 0) {
        printf("Can not attach SHM supervisor buffer of size %lu", sizeof(struct conn_info));
        return 0;
    }

    if ((shm_conn_info = (struct conn_info *)shmat(shmid, NULL, 0)) == (struct conn_info *) - 1) {
        printf("Main shm not ready yet (netlink server)");
        return 0;
    }
    if(shm_conn_info->max_stuck_buf_len > 100) {
        exit(1);
    }
    exit(0);

    return 0;
}
