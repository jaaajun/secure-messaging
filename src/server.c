#include "protocol.h"
#include "log.h"
#include "secure.h"
#include "database.h"
#include "queue.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <semaphore.h>
#include <mysql/mysql.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <stdbool.h>

struct thread_info
{
    pthread_t thread;
    int channel;
};

struct chat_rw_thread_info
{
    pthread_t thread;
    int channel;
    const unsigned char * key;
    const unsigned char * iv;
    const char * username;
    const char * peername;
    pthread_mutex_t * exit_flag_lock;
    volatile int * exit_flag;
};

static sem_t thread_sem;
static struct thread_info threads[SERVER_MAX_CLIENT_NUM];
static struct queue * q;

static void database_warmup(void);
static void * thread_start_routine(void * arg);

int main(int argc, char ** argv)
{
    int server_socket, channel;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addrlen;
    struct thread_info * info;

    log_init();
    secure_server_init();
    database_init();
    database_warmup();
    sem_init(&thread_sem, 0, SERVER_MAX_CLIENT_NUM);
    q = queue_init(SERVER_MAX_CLIENT_NUM);
    for (int i = 0; i < SERVER_MAX_CLIENT_NUM; ++i) {
        enqueue(q, &(threads[i]));
    }

    server_socket = socket(AF_INET, SOCK_STREAM, 0);

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_aton(SERVER_IP, &(server_addr.sin_addr));
    bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr));

    listen(server_socket, SERVER_MAX_CLIENT_NUM);

    log_print(LOG_INFO, "server: starts");

    while (true)
    {
        sem_wait(&thread_sem);
        info = (struct thread_info *)dequeue(q);

        addrlen = sizeof(client_addr);
        channel = accept(server_socket, (struct sockaddr *)&client_addr, &addrlen);

        if (channel == -1)
        {
            enqueue(q, info);
            sem_post(&thread_sem);
            log_print(LOG_ERROR, "server: accept() fails with errno: %d", errno);
            continue;
        }

        log_print(LOG_INFO, "server: thread %d/%d establishes connection with: %s:%hu",
                            (int)(info - threads),
                            SERVER_MAX_CLIENT_NUM - 1,
                            inet_ntoa(client_addr.sin_addr),
                            ntohs(client_addr.sin_port));

        info->channel = channel;
        pthread_create(&(info->thread), NULL, thread_start_routine, info);
    }

    close(server_socket);
    queue_finish(q);
    sem_destroy(&thread_sem);
    database_finish();
    secure_server_finish();
    log_finish();

    return 0;
}

static void database_warmup(void)
{
    MYSQL * mysql;

    mysql = database_connect();
    database_create_table(mysql, "user", 
            "username varchar(64) character set utf8mb4 not null primary key, \
             password varchar(64) character set utf8mb4 not null");
    database_create_table(mysql, "friend", 
            "username1 varchar(64) character set utf8mb4 not null, \
             username2 varchar(64) character set utf8mb4 not null, \
             state tinyint not null, \
             primary key (username1, username2)");
    database_create_table(mysql, "message", 
            "id bigint not null auto_increment primary key, \
             username1 varchar(64) character set utf8mb4 not null, \
             username2 varchar(64) character set utf8mb4 not null, \
             time double not null, \
             content varchar(800) character set utf8mb4, \
             state tinyint not null");
    database_disconnect(mysql);
}

static int _database_row_exist(MYSQL * mysql, 
                               const char * table,
                               const char * row_constraint)
{
    result_t * result;
    int ret;

    database_select(mysql, table, "*", row_constraint);
    result = database_get_result(mysql);
    if (result->r > 0) {
        ret = 1;
    } else {
        ret = 0;
    }
    database_free_result(result);

    return ret;
}

/** _sign_in return value:
 *     return  0 if succeed
 *     return -1 if fail
 *     return -3 if meet error (unused)
*/
static int _sign_in(MYSQL * mysql, 
                    const char * username, 
                    const char * password) {
    char row_constraint[256];
    int ret;

    snprintf(row_constraint, 256, "where username = \'%s\' and password = \'%s\'", 
                                    username, password);
    if (_database_row_exist(mysql, "user", row_constraint)) {
        ret = 0;
    } else {
        ret = -1;
    }

    return ret;
}

/** _sign_up return value:
 *   return  0 if succeed
 *   return -1 if fail
 *   return -3 if meet error (unused)
*/
static int _sign_up(MYSQL * mysql, 
                    const char * username, 
                    const char * password) {
    char buf[256];
    int ret;

    snprintf(buf, 256, "where username = \'%s\'", username);
    if (_database_row_exist(mysql, "user", buf)) {
        ret = -1;
    } else {
        snprintf(buf, 256, "\'%s\', \'%s\'", username, password);
        database_insert(mysql, "user", "username, password", buf);
        ret = 0;
    }

    return ret;
}

/** _authentication return value:
 *     return  0 if succeed
 *     return -1 if receive disconnect flag
 *     return -2 if connection is broken
 *     return -3 if meet error
 *     return -4 if message format is incorrect
*/
static int _authentication(int channel, 
                            const unsigned char * key, 
                            const unsigned char * iv, 
                            MYSQL * mysql, 
                            char * username)
{
    char buf[256];
    int ret;

    while (true) {
        ret = secure_recv(channel, buf, 131, 0, key, iv);
        if (ret > 0) {
            if (buf[0] == PROTOCOL_DISCONNECT) {
                return -1;
            } else if (buf[0] != PROTOCOL_SIGN_IN && buf[0] != PROTOCOL_SIGN_UP) {
                return -4;
            } else {
                if (buf[0] == PROTOCOL_SIGN_IN) {
                    ret = _sign_in(mysql, &(buf[1]), &(buf[66]));
                } else {
                    ret = _sign_up(mysql, &(buf[1]), &(buf[66]));
                }
                if (ret == 0) {
                    buf[0] = PROTOCOL_SUCCEED;
                    secure_send(channel, buf, 1, 0, key, iv);
                    strcpy(username, &(buf[1]));
                    break;
                } else if (ret == -1) {
                    buf[0] = PROTOCOL_FAIL;
                    secure_send(channel, buf, 1, 0, key, iv);
                } else {
                    return ret;
                }
            }
        } else if (ret == 0) {
            return -2;
        } else {
            return -3;
        }
    }

    return 0;
}

static int _send_friendlist(int channel, 
                            const unsigned char * key, 
                            const unsigned char * iv, 
                            MYSQL * mysql, 
                            const char * username,
                            int flag)
{
    result_t * result;
    char buf[256];
    int state;

    snprintf(buf, 256, "where username1 = \'%s\' or username2 = \'%s\' order by state", 
                        username, username);
    database_select(mysql, "friend", "*", buf);
    result = database_get_result(mysql);
    for (int i = 0; i < result->r; ++i) {
        state = (int)strtol(result->rows[i][2], NULL, 10);
        if (state & flag) {
            buf[0] = PROTOCOL_FRIEND_LIST;
            if (strcmp(username, result->rows[i][0])) {
                strcpy(&(buf[1]), result->rows[i][0]);
            } else {
                strcpy(&(buf[1]), result->rows[i][1]);
            }
            buf[66] = (char)state;
            secure_send(channel, buf, 67, 0, key, iv);
        }
    }
    database_free_result(result);
    buf[0] = PROTOCOL_FRIEND_LIST_END;
    secure_send(channel, buf, 67, 0, key, iv);

    return 0;
}

/** _friend_add return value:
 *     return  0 if succeed
 *     return -1 if fail
 *         - already send/being state
 *     return -4 if message format is incorrect
 *         - peername does not exist
 *         - peername == username
*/
static int _friend_add(MYSQL * mysql,
                       const char * username,
                       const char * peername)
{
    result_t * result;
    char buf[256];
    char assignment[16];
    const char * holder[2];
    int holder_username_index;
    int state;
    int ret;

    snprintf(buf, 256, "where username = \'%s\'", peername);
    if (_database_row_exist(mysql, "user", buf)) {
        ret = strcmp(username, peername);
        if (ret == 0) {
            return -4;
        } else if (ret < 0) {
            holder[0] = username;
            holder[1] = peername;
            holder_username_index = 0;
        } else {
            holder[0] = peername;
            holder[1] = username;
            holder_username_index = 1;
        }

        snprintf(buf, 256, "where username1 = \'%s\' and username2 = \'%s\'", 
                            holder[0], holder[1]);
        database_select(mysql, "friend", "*", buf);
        result = database_get_result(mysql);
        if (result->r == 0) {
            state = TABLE_F_STATE_NULL;
        } else {
            state = (int)strtol(result->rows[0][2], NULL, 10);
        }
        database_free_result(result);

        if (state == TABLE_F_STATE_NULL) {
            if (holder_username_index == 0) {
                snprintf(buf, 256, "\'%s\', \'%s\', %d", holder[0], holder[1], TABLE_F_STATE_SEND);
            } else {
                snprintf(buf, 256, "\'%s\', \'%s\', %d", holder[0], holder[1], TABLE_F_STATE_RECV);
            }
            database_insert(mysql, "friend", "username1, username2, state", buf);
            return 0;
        } else if (state == TABLE_F_STATE_SEND) {
            if (holder_username_index == 0) {
                return -1;
            } else {
                state = TABLE_F_STATE_BEING;
            }
        } else if (state == TABLE_F_STATE_RECV) {
            if (holder_username_index == 0) {
                state = TABLE_F_STATE_BEING;
            } else {
                return -1;
            }
        } else if (state == TABLE_F_STATE_SEND_REJ || state == TABLE_F_STATE_RECV_REJ) {
            if (holder_username_index == 0) {
                state = TABLE_F_STATE_SEND;
            } else {
                state = TABLE_F_STATE_RECV;
            }
        } else {
            return -1;
        }
    } else {
        return -4;
    }

    snprintf(assignment, 16, "state = %d", state);
    database_update(mysql, "friend", assignment, buf);

    return 0;
}

/** _friend_accept return value:
 *     return  0 if succeed
 *     return -4 if message format is incorrect
 *         - no request from peername
 *         - peername == username
*/
static int _friend_accept(MYSQL * mysql,
                          const char * username,
                          const char * peername)
{
    result_t * result;
    char buf[256];
    char assignment[16];
    const char * holder[2];
    int state, target_state;
    int ret;

    ret = strcmp(username, peername);
    if (ret == 0) {
        return -4;
    } else if (ret < 0) {
        holder[0] = username;
        holder[1] = peername;
        target_state = TABLE_F_STATE_RECV;
    } else {
        holder[0] = peername;
        holder[1] = username;
        target_state = TABLE_F_STATE_SEND;
    }

    snprintf(buf, 256, "where username1 = \'%s\' and username2 = \'%s\'", 
                        holder[0], holder[1]);
    database_select(mysql, "friend", "*", buf);
    result = database_get_result(mysql);
    if (result->r == 0) {
        database_free_result(result);
        return -4;
    } else {
        state = (int)strtol(result->rows[0][2], NULL, 10);
        database_free_result(result);
        if (state == target_state) {
            snprintf(assignment, 16, "state = %d", TABLE_F_STATE_BEING);
            database_update(mysql, "friend", assignment, buf);
        } else {
            return -4;
        }
    }

    return 0;
}

/** _friend_reject return value:
 *     return  0 if succeed
 *     return -4 if message format is incorrect
 *         - no request from peername
 *         - peername == username
*/
static int _friend_reject(MYSQL * mysql,
                          const char * username,
                          const char * peername)
{
    result_t * result;
    char buf[256];
    char assignment[16];
    const char * holder[2];
    int state, target_state;
    int ret;

    ret = strcmp(username, peername);
    if (ret == 0) {
        return -4;
    } else if (ret < 0) {
        holder[0] = username;
        holder[1] = peername;
        target_state = TABLE_F_STATE_RECV;
    } else {
        holder[0] = peername;
        holder[1] = username;
        target_state = TABLE_F_STATE_SEND;
    }

    snprintf(buf, 256, "where username1 = \'%s\' and username2 = \'%s\'", 
                        holder[0], holder[1]);
    database_select(mysql, "friend", "*", buf);
    result = database_get_result(mysql);
    if (result->r == 0) {
        database_free_result(result);
        return -4;
    } else {
        state = (int)strtol(result->rows[0][2], NULL, 10);
        database_free_result(result);
        if (state == target_state) {
            /* state_x_rej = state_x << 1 */
            snprintf(assignment, 16, "state = %d", state << 1);
            database_update(mysql, "friend", assignment, buf);
        } else {
            return -4;
        }
    }

    return 0;
}

/** _friend return value:
 *     return  0 if succeed
 *     return -2 if connection is broken
 *     return -3 if meet error
 *     return -4 if message format is incorrect
*/
static int _friend(int channel, 
                   const unsigned char * key, 
                   const unsigned char * iv, 
                   MYSQL * mysql, 
                   const char * username)
{
    char buf[128];
    int ret;

    while (true) {
        _send_friendlist(channel, key, iv, mysql, username, 
                TABLE_F_STATE_SEND | TABLE_F_STATE_RECV | TABLE_F_STATE_BEING);

        ret = secure_recv(channel, buf, 66, 0, key, iv);
        if (ret > 0) {
            if (buf[0] == PROTOCOL_FINISH) {
                break;
            } else if (buf[0] != PROTOCOL_FRIEND_ADD &
                       buf[0] != PROTOCOL_FRIEND_ACCEPT &
                       buf[0] != PROTOCOL_FRIEND_REJECT) {
                return -4;
            } else {
                if (buf[0] == PROTOCOL_FRIEND_ADD) {
                    ret = _friend_add(mysql, username, &(buf[1]));
                } else if (buf[0] == PROTOCOL_FRIEND_ACCEPT) {
                    ret = _friend_accept(mysql, username, &(buf[1]));
                } else {
                    ret = _friend_reject(mysql, username, &(buf[1]));
                }
                if (ret == 0) {
                    buf[0] = PROTOCOL_SUCCEED;
                } else if (ret == -1) {
                    buf[0] = PROTOCOL_FAIL;
                } else {
                    buf[0] = PROTOCOL_ERROR;
                }
                secure_send(channel, buf, 1, 0, key, iv);
            }
        } else if (ret == 0) {
            return -2;
        } else {
            return -3;
        }
    }

    return 0;
}

static int _send_messagelist(int channel, 
                             const unsigned char * key, 
                             const unsigned char * iv, 
                             MYSQL * mysql, 
                             const char * username, 
                             const char * peername, 
                             uint64_t * message_id)
{
    result_t * result;
    uint64_t current_id;
    char buf[1024];
    char assignment[16];
    char constraint[64];
    int is_receiver;
    int state;

    snprintf(buf, 1024, "where id > %lu and ( \
                            (username1 = \'%s\' and username2 = \'%s\') or \
                            (username1 = \'%s\' and username2 = \'%s\') \
                        ) order by time", 
                        *message_id, username, peername, peername, username);
    database_select(mysql, "message", "*", buf);
    result = database_get_result(mysql);
    for (int i = 0; i < result->r; ++i) {
        buf[0] = PROTOCOL_CHAT_LIST;
        is_receiver = strcmp(username, result->rows[i][1]);
        if (is_receiver) {
            buf[1] = PROTOCOL_CHAT_LIST_RECV;
        } else {
            buf[1] = PROTOCOL_CHAT_LIST_SEND;
        }
        *((double *)(&(buf[2]))) = strtod(result->rows[i][3], NULL);
        strcpy(&(buf[10]), result->rows[i][4]);
        state = (int)strtol(result->rows[i][5], NULL, 10);
        buf[811] = (char)state;
        secure_send(channel, buf, 812, 0, key, iv);

        current_id = strtoull(result->rows[i][0], NULL, 10);
        if (current_id > *message_id) {
            *message_id = current_id;
        }

        if (is_receiver && state == TABLE_M_STATE_UNREAD) {
            snprintf(assignment, 16, "state = %d", TABLE_M_STATE_READ);
            snprintf(constraint, 64, "where id = %lu", current_id);
            database_update(mysql, "message", assignment, constraint);
        }
    }
    database_free_result(result);
    buf[0] = PROTOCOL_CHAT_LIST_END;
    secure_send(channel, buf, 812, 0, key, iv);

    return 0;
}

/** _chat_select return value:
 *     return  0 if succeed
 *     return -4 if message format is incorrect
 *         - peername is not in the friend list
 *         - peername == username
*/
static int _chat_select(MYSQL * mysql, 
                        const char * username, 
                        const char * peername) {
    
    char row_constraint[256];
    const char * holder[2];
    int ret;

    ret = strcmp(username, peername);
    if (ret == 0) {
        return -4;
    } else if (ret < 0) {
        holder[0] = username;
        holder[1] = peername;
    } else {
        holder[0] = peername;
        holder[1] = username;
    }

    snprintf(row_constraint, 256, 
                "where username1 = \'%s\' and username2 = \'%s\' and state = %d", 
                holder[0], holder[1], TABLE_F_STATE_BEING);
    if (0 == _database_row_exist(mysql, "friend", row_constraint)) {
        return -4;
    }

    return 0;
}

/** chat_r_thread_routine return value:
 *     return  0 if succeed
 *     return -2 if connection is broken
 *     return -3 if meet error
 *     return -4 if message format is incorrect
*/
static void * chat_r_thread_routine(void * arg)
{
    struct chat_rw_thread_info * info;
    MYSQL * mysql;
    char buf[1024];
    char value[1024];
    int ret;

    info = arg;

    database_thread_init();
    mysql = database_connect();

    while (true) {
        ret = secure_recv(info->channel, buf, 810, 0, info->key, info->iv);
        if (ret > 0) {
            if (buf[0] == PROTOCOL_FINISH) {
                ret = 0;
                break;
            } else if (buf[0] == PROTOCOL_CHAT_MESSAGE) {
                snprintf(value, 1024, "\'%s\', \'%s\', %lf, \'%s\', %d", 
                                        info->username, 
                                        info->peername, 
                                        *((double *)(&(buf[1]))), 
                                        &(buf[9]), 
                                        TABLE_M_STATE_UNREAD);
                database_insert(mysql, 
                                "message", 
                                "username1, username2, time, content, state", 
                                value);
            } else {
                ret = -4;
                break;
            }
        } else if (ret == 0) {
            ret = -2;
            break;
        } else {
            ret = -3;
            break;
        }
    }

    database_disconnect(mysql);
    database_thread_finish();

    return (void *)ret;
}

static void * chat_w_thread_routine(void * arg)
{
    struct chat_rw_thread_info * info;
    struct timespec ts;
    MYSQL * mysql;
    uint64_t message_id = 0;
    int exit_flag = 0;
    char buf[1024];

    info = arg;

    ts.tv_sec = (time_t)(SERVER_CHAT_SYN_INTERVAL);
    ts.tv_nsec = (SERVER_CHAT_SYN_INTERVAL - ts.tv_sec) * 1e9;

    database_thread_init();
    mysql = database_connect();

    while (true) {
        _send_messagelist(info->channel, info->key, info->iv, 
                          mysql, info->username, info->peername, &message_id);

        #ifdef MULTICORE
            while (pthread_mutex_trylock(info->exit_flag_lock)) { ; }
        #else
            pthread_mutex_lock(info->exit_flag_lock);
        #endif /* MULTICORE */
        if (*(info->exit_flag)) {
            exit_flag = 1;
        }
        pthread_mutex_unlock(info->exit_flag_lock);

        if (exit_flag) {
            buf[0] = PROTOCOL_FINISH;
            secure_send(info->channel, buf, 812, 0, info->key, info->iv);
            break;
        }

        nanosleep(&ts, NULL);
    }

    database_disconnect(mysql);
    database_thread_finish();

    return NULL;
}

/** _chat return value:
 *     return  0 if succeed
 *     return -2 if connection is broken
 *     return -3 if meet error
 *     return -4 if message format is incorrect
*/
static int _chat(int channel, 
                 const unsigned char * key, 
                 const unsigned char * iv, 
                 MYSQL * mysql, 
                 const char * username, 
                 struct thread_info * info)
{
    /* 0 for r_thread, 1 for w_thread */
    struct chat_rw_thread_info rw_threads[2];
    pthread_mutex_t exit_flag_lock;
    volatile int exit_flag;
    char buf[128];
    int ret;

    _send_friendlist(channel, key, iv, mysql, username, TABLE_F_STATE_BEING);

    while (true) {
        ret = secure_recv(channel, buf, 66, 0, key, iv);
        if (ret > 0) {
            if (buf[0] == PROTOCOL_FINISH) {
                break;
            } else if (buf[0] == PROTOCOL_CHAT_SELECT) {
                if (0 == _chat_select(mysql, username, &(buf[1]))) {
                    buf[0] = PROTOCOL_SUCCEED;
                    secure_send(channel, buf, 1, 0, key, iv);
                    database_disconnect(mysql);
                    /* database_thread_finish(); */

                    log_print(LOG_INFO, "thread %d/%d: %s chats with %s", 
                                        (int)(info - threads), 
                                        SERVER_MAX_CLIENT_NUM - 1, 
                                        username, &(buf[1]));

                    /* spawn read / write threads */
                    rw_threads[0].channel = rw_threads[1].channel = channel;
                    rw_threads[0].key = rw_threads[1].key = key;
                    rw_threads[0].iv = rw_threads[1].iv = iv;
                    rw_threads[0].username = rw_threads[1].username = username;
                    rw_threads[0].peername = rw_threads[1].peername = &(buf[1]);
                    pthread_mutex_init(&exit_flag_lock, NULL);
                    rw_threads[0].exit_flag_lock = NULL;
                    rw_threads[1].exit_flag_lock = &exit_flag_lock;
                    exit_flag = 0;
                    rw_threads[0].exit_flag = NULL;
                    rw_threads[1].exit_flag = &exit_flag;
                    pthread_create(&(rw_threads[0].thread), 
                                    NULL, 
                                    chat_r_thread_routine, 
                                    &(rw_threads[0]));
                    pthread_create(&(rw_threads[1].thread), 
                                    NULL, 
                                    chat_w_thread_routine, 
                                    &(rw_threads[1]));
                    pthread_join(rw_threads[0].thread, (void **)&(ret));
                    #ifdef MULTICORE
                        while (pthread_mutex_trylock(&exit_flag_lock)) { ; }
                    #else
                        pthread_mutex_lock(&exit_flag_lock);
                    #endif /* MULTICORE */
                    exit_flag = 1;
                    pthread_mutex_unlock(&exit_flag_lock);
                    pthread_join(rw_threads[1].thread, NULL);
                    pthread_mutex_destroy(&exit_flag_lock);

                    /* database_thread_init(); */
                    mysql = database_connect();
                    if (ret != 0) {
                        return ret;
                    }
                } else {
                    buf[0] = PROTOCOL_ERROR;
                    secure_send(channel, buf, 1, 0, key, iv);
                }
            } else {
                return -4;
            }
        } else if (ret == 0) {
            return -2;
        } else {
            return -3;
        }
    }

    return 0;
}

static void * thread_start_routine(void * arg)
{
    struct thread_info * info;
    unsigned char key[32];
    unsigned char iv[16];
    MYSQL * mysql;
    char username[65] = {0};
    char buf[16];

    info = arg;

    secure_server_buildkey(info->channel, key, iv);
    database_thread_init();
    mysql = database_connect();

    if (0 == _authentication(info->channel, key, iv, mysql, username)) {
        log_print(LOG_INFO, "thread %d/%d: %s says \"hello, world!\"", 
                            (int)(info - threads), 
                            SERVER_MAX_CLIENT_NUM - 1, 
                            username);

        while (secure_recv(info->channel, buf, 1, 0, key, iv) > 0) {
            if (buf[0] == PROTOCOL_DISCONNECT) {
                break;
            } else if (buf[0] == PROTOCOL_FRIEND) {
                if (0 != _friend(info->channel, key, iv, mysql, username)) {
                    break;
                }
            } else if (buf[0] == PROTOCOL_CHAT) {
                if (0 != _chat(info->channel, key, iv, mysql, username, info)) {
                    break;
                }
            } else {
                break;
            }
        }

        log_print(LOG_INFO, "thread %d/%d: %s says \"bye!\"", 
                            (int)(info - threads), 
                            SERVER_MAX_CLIENT_NUM - 1, 
                            username);
    }

    database_disconnect(mysql);
    database_thread_finish();
    close(info->channel);
    info->channel = -1;
    enqueue(q, info);
    sem_post(&thread_sem);

    log_print(LOG_INFO, "server: thread %d/%d disconnects",
                        (int)(info - threads),
                        SERVER_MAX_CLIENT_NUM - 1);

    return NULL;
}
