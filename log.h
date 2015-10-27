#ifndef _VTUN_LOG_H
#define _VTUN_LOG_H

#include "config.h"

#include <semaphore.h>

#include "vtun.h"

#define	LOG_EMERG	0	/* system is unusable */
#define	LOG_ALERT	1	/* action must be taken immediately */
#define	LOG_CRIT	2	/* critical conditions */
#define	LOG_ERR		3	/* error conditions */
#define	LOG_WARNING	4	/* warning conditions */
#define	LOG_NOTICE	5	/* normal but significant condition */
#define	LOG_INFO	6	/* informational */
#define	LOG_DEBUG	7	/* debug-level messages */

void vlog_shm_set(int state, sem_t *logSem, char *log, int *counter, int size);
void vlog_shm_print(int priority, char *format, ...);
void vlog_shm_process(struct conn_info *shm_conn_info);

void vlog_init();
void vlog_free();

void vlog_open(const char *ident, int option, int facility);
void vlog_close();

void vlog (int priority, char *format, ...);

#endif // _VTUN_LOG_H