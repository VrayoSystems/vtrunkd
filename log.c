#include "config.h"

#include "log.h"

#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/time.h>

#include "lib.h"
#include "vtun.h"

#define SYSLOG_DUPS 3
char *syslog_buf[SYSLOG_DUPS];
int syslog_buf_counter = 0;
int syslog_dup_counter = 0;
int syslog_sequential_counter = 0;
int syslog_dup_type = 0; //0 - dups no found 1 - single dup 2 - double dup
int init = 0;

#define SYSLOG_HOST_LEN 256
char syslog_host[SYSLOG_HOST_LEN] = { 0x00 };

int shm_log_state = 0; // 0 - regular log 1 - over shm
struct {
    sem_t *logSem;
    char *log;
    int *pointer;       // Points after last string-termination zero byte.
    int size;
} shm_syslog = { NULL, NULL, NULL, 0 };

void vlog_shm_set(int state, sem_t *logSem, char *log, int *counter, int size) {
    shm_log_state = state;
    if (state) {
        shm_syslog.logSem = logSem;
        shm_syslog.log = log;
        shm_syslog.pointer = counter;
        shm_syslog.size = size;
    } else {
        shm_syslog.logSem = NULL;
        shm_syslog.log = NULL;
        shm_syslog.pointer = NULL;
        shm_syslog.size = 0;
    }
}

void vlog_shm_print(int priority, char *format, ...) {
    va_list ap;
    va_start(ap, format);
    if (shm_log_state) {
        char buf[JS_MAX];
        int str_len = vsnprintf(buf, sizeof(buf), format, ap);
        sem_wait(shm_syslog.logSem);
        if (shm_syslog.size - *(shm_syslog.pointer) < str_len + 1) { // str_len + zero terminate
            memcpy(shm_syslog.log + * (shm_syslog.pointer), buf, shm_syslog.size - * (shm_syslog.pointer));
            memcpy(shm_syslog.log, buf + (shm_syslog.size - * (shm_syslog.pointer)), (str_len + 1) - (shm_syslog.size - * (shm_syslog.pointer)));
            *(shm_syslog.pointer) = (str_len + 1) - (shm_syslog.size - * (shm_syslog.pointer));
        } else {
            memcpy(shm_syslog.log + * (shm_syslog.pointer), buf, str_len + 1);
            *shm_syslog.pointer += str_len + 1;
        }
        sem_post(shm_syslog.logSem);
    } else {
        vsyslog(priority, format, ap);
    }
    va_end(ap);
}

//
//  TODO: Handle loglevel.
//
void vlog_shm_process(struct conn_info *shm_conn_info) {
    static int logPointer = 0;
    static char buf[JS_MAX] = { 0x00 };

    /* Log checking */
    int totalLen = 0; // to prevent race condition total log len no more SHM_SYSLOG
    while (1) {
        if (totalLen >= SHM_SYSLOG)
            break;

        sem_wait(&shm_conn_info->syslog.logSem);

        // Nothing to log.
        if (logPointer == shm_conn_info->syslog.counter) {
            sem_post(&shm_conn_info->syslog.logSem);
            break;
        }

        ssize_t availLen = (shm_conn_info->syslog.counter - logPointer + SHM_SYSLOG) % SHM_SYSLOG;
        ssize_t bufLen = sizeof(buf);
        ssize_t retLen = 0;

        if (availLen < SHM_SYSLOG - logPointer) {
            retLen = snprintf(buf, bufLen, "%s", shm_conn_info->syslog.log + logPointer);
        } else {
            ssize_t maxLen = min(bufLen, SHM_SYSLOG - logPointer);
            retLen = snprintf(buf, maxLen, "%s", shm_conn_info->syslog.log + logPointer);
            // { '\0', ..., '\0', 'H', 'e', 'l', 'l', 'o' } -+
            //    ^                                          |
            //    +------------------------------------------+
            if ((retLen == SHM_SYSLOG - logPointer) && (shm_conn_info->syslog.log[0] != 0) && bufLen > retLen + 1) {
                maxLen = sizeof(buf) - retLen;
                retLen += snprintf(buf + retLen, maxLen, "%s", shm_conn_info->syslog.log);
            }
        }

        totalLen += retLen + 1;
        logPointer = (logPointer+ retLen + 1) % SHM_SYSLOG;

        sem_post(&shm_conn_info->syslog.logSem);
        // TODO: Why not syslog(buf)?
        syslog(LOG_INFO, "%s", buf);
    }
}


void vlog_init() {
    for (int i = 0; i < SYSLOG_DUPS; i++) {
        syslog_buf[i] = malloc(JS_MAX);
        memset(syslog_buf[i], 0, JS_MAX);
    }
    init = 1;
}

void vlog_free() {
    for (int i = 0; i < SYSLOG_DUPS; i++) {
        free(syslog_buf[i]);
    }
    init = 0;
}

void vlog_open(const char *ident, int option, int facility) {
    strncpy(syslog_host, ident, SYSLOG_HOST_LEN);
    openlog(syslog_host, option, facility);
}

void vlog_close() {
    closelog();
}

void vlog(int priority, char *format, ...) {
#ifdef SYSLOG
    if(vtun.quiet && priority != LOG_ERR) return;
    static volatile sig_atomic_t in_syslog = 0;
    char buf[JS_MAX];
    va_list ap;
    int print = 0;

    if (!in_syslog) {
        in_syslog = 1;

        va_start(ap, format);
        vsnprintf(buf, sizeof(buf) - 1, format, ap);
        va_end(ap);
        if (init) {
            if (syslog_dup_type == 0) {
//                syslog(priority, "type 1 test counter %d %s new - %s",syslog_buf_counter,syslog_buf[syslog_buf_counter], buf);

                if (!strcmp(syslog_buf[syslog_buf_counter], buf)) {
                    syslog_dup_counter++;
                    syslog_dup_type = 1;
                    syslog_sequential_counter = 0;
//                    syslog(priority, "type %d raise",syslog_dup_type);
                } else {
                    int counter = syslog_buf_counter - 1;
                    if (counter < 0) {
                        counter = SYSLOG_DUPS - 1;
                    }
//                    syslog(priority, "type 2 test buf %d counter %d %s new - %s",syslog_buf_counter,counter,syslog_buf[counter], buf);
                    if (!strcmp(syslog_buf[counter], buf)) {
                        syslog_dup_counter++;
                        syslog_dup_type = 2;
//                        syslog(priority, "type %d raise",syslog_dup_type);
                        syslog_sequential_counter = 0;
                    } else {
                        if (--counter < 0) {
                            counter = SYSLOG_DUPS - 1;
                        }
//                        syslog(priority, "type 3 test buf %d counter %d %s new - %s",syslog_buf_counter,counter,syslog_buf[counter], buf);

                        if (!strcmp(syslog_buf[counter], buf)) {
                            syslog_dup_counter++;
                            syslog_dup_type = 3;
                            syslog_sequential_counter = 1;
//                            syslog(priority, "type %d raise",syslog_dup_type);
                        } else {
                            if (++syslog_buf_counter == SYSLOG_DUPS) {
                                syslog_buf_counter = 0;
                            }
                            int string_len = strlen(buf);
                            if (string_len > JS_MAX) {
                                string_len = JS_MAX - 2;
                            }
//                            syslog(priority, "first save test buf %d %s",syslog_buf_counter, buf);
                            memcpy(syslog_buf[syslog_buf_counter], buf, string_len + 1);
                            print = 1;
                        }
                    }
                }
            } else if (syslog_dup_type == 1) {
                if (syslog_sequential_counter < 0) {
                    syslog_sequential_counter = syslog_dup_type - 1;
                }
                int counter = syslog_buf_counter - syslog_sequential_counter;
                if (counter < 0) {
                    counter = syslog_buf_counter - syslog_sequential_counter + (SYSLOG_DUPS - 1);
                }
//                syslog(priority, "type %d buf_counter %d sequential_counter %d counter %d log:\"%s\"",syslog_dup_type,syslog_buf_counter, syslog_sequential_counter, counter, syslog_buf[counter]);

                if (!strcmp(syslog_buf[counter], buf)) {
                    syslog_sequential_counter--;
                    syslog_dup_counter++;
                } else {
                    if (++syslog_buf_counter == SYSLOG_DUPS) {
                        syslog_buf_counter = 0;
                    }
                    int string_len = strlen(buf);
                    if (string_len > JS_MAX) {
                        string_len = JS_MAX - 2;
                    }
                    memcpy(syslog_buf[syslog_buf_counter], buf, string_len + 1);
                    print = 1;
                }
            } else if (syslog_dup_type == 2) {
                if (syslog_sequential_counter < 0) {
                    syslog_sequential_counter = syslog_dup_type - 1;
                }
                int counter = syslog_buf_counter - syslog_sequential_counter;
                if (counter < 0) {
                    counter = syslog_buf_counter - syslog_sequential_counter + (SYSLOG_DUPS );
                }
//               syslog(priority, "type %d buf_counter %d sequential_counter %d counter %d log:\"%s\"",syslog_dup_type,syslog_buf_counter, syslog_sequential_counter, counter, syslog_buf[counter]);
                if (!strcmp(syslog_buf[counter], buf)) {
                    syslog_sequential_counter--;
                    syslog_dup_counter++;
                } else {
                    if (++syslog_buf_counter == SYSLOG_DUPS) {
                        syslog_buf_counter = 0;
                    }
                    int string_len = strlen(buf);
                    if (string_len > JS_MAX) {
                        string_len = JS_MAX - 2;
                    }
                    memcpy(syslog_buf[syslog_buf_counter], buf, string_len + 1);
                    print = 1;
                }
            }  else if (syslog_dup_type == 3) {
                if (syslog_sequential_counter < 0) {
                    syslog_sequential_counter = syslog_dup_type - 1;
                }
                int counter = syslog_buf_counter - syslog_sequential_counter;
                if (counter < 0) {
                    counter = syslog_buf_counter - syslog_sequential_counter + (SYSLOG_DUPS );
                }
//                syslog(priority, "type %d buf_counter %d sequential_counter %d counter %d log:\"%s\"",syslog_dup_type,syslog_buf_counter, syslog_sequential_counter, counter, syslog_buf[counter]);
                if (!strcmp(syslog_buf[counter], buf)) {
                    syslog_sequential_counter--;
                    syslog_dup_counter++;
                } else {
                    if (++syslog_buf_counter == SYSLOG_DUPS) {
                        syslog_buf_counter = 0;
                    }
                    int string_len = strlen(buf);
                    if (string_len > JS_MAX) {
                        string_len = JS_MAX - 2;
                    }
                    memcpy(syslog_buf[syslog_buf_counter], buf, string_len + 1);
                    print = 1;
                }
            }
        } else {
            print = 1;
        }

        if (print) {
            struct timeval ts;
            gettimeofday(&ts, NULL);

            if (syslog_dup_counter) {
                vlog_shm_print(priority, "%s [%" PRIu64 "]: Last %d message(s) repeat %d times dups %d", syslog_host, tv2ms(&ts), syslog_dup_type, syslog_dup_counter / syslog_dup_type + 1, syslog_dup_counter);
                syslog_dup_counter = 0;
                syslog_dup_type = 0;
                syslog_sequential_counter = 0;
                for (int i = 0; i < SYSLOG_DUPS; i++) {
                    if (i == syslog_buf_counter)
                        continue;
                    memset(syslog_buf[i], 0, JS_MAX);
                }

            }

            vlog_shm_print(priority, "%s [%" PRIu64 "]: %s", syslog_host, tv2ms(&ts), buf);
        }
        in_syslog = 0;
    }
#else
    return;
#endif
}