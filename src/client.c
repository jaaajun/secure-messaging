#include "protocol.h"
#include "secure.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>

static int channel;
static unsigned char key[32];
static unsigned char iv[16];
static char username[65];

static void start_routine(void);

int main(int argc, char * argv[])
{
    int client_socket;
    struct sockaddr_in server_addr;

    secure_client_init();

    client_socket = socket(AF_INET, SOCK_STREAM, 0);

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_aton(SERVER_IP, &(server_addr.sin_addr));

    if (0 == connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr))) {
        channel = client_socket;
        start_routine();
    }

    close(client_socket);

    secure_client_finish();

    return 0;
}

static int _helper_get_int(int * int_addr)
{
    int c;
    int ret;

    ret = scanf("%d", int_addr);
    if (ret == 1) {
        ret = 0;
    } else {
        ret = -1;
    }

    while ((c = getchar()) != '\n' && c != EOF) { ; }

    return ret;
}

/** _helper_get_string return value: 
 *     return  0 if succeed
 *     return -1 if overflow
 *     return -2 if meet EOF
 *  _helper_get_string note: 
 *     fill at most (string_max_size - 1) characters
 *     example:
 *         "a"   -> [_ _ _]: [a \0  _]
 *         "ab"  -> [_ _ _]: [a  b \0]
 *         "abc" -> [_ _ _]: [a  b \0]
*/
static int _helper_get_string(char * string_addr, int string_max_size)
{
    int index;
    int c;

    for (index = 0; index < string_max_size - 1; ++index) {
        if ((c = getchar()) == '\n' || c == EOF) { break; }
        string_addr[index] = c;
    }

    string_addr[index] = '\0';
    
    if (c == EOF) {
        return -2;
    } else if (c != '\n') {
        while ((c = getchar()) != '\n' && c != EOF) { ; }
        if (c == '\n') {
            return -1;
        } else {
            return -2;
        }
    }

    return 0;
}

static void _helper_put_file(FILE * file)
{
    int c;

    rewind(file);

    while ((c = fgetc(file)) != EOF) {
        putchar(c);
    }
}

static void _welcome(void)
{
    printf("\n");
    printf(">> Hello, Secure Messaging!\n");
}

static void _pause(void)
{
    int c;

    printf("\n");
    printf(">> press ENTER to continue...");

    while ((c = getchar()) != '\n' && c != EOF) { ; }
}

static void _clear(void)
{
    printf("\e[1;1H\e[2J");
}

static void _help(int chapter)
{
    printf("\n");

    switch (chapter)
    {
    case 1:
        printf(">> sign in and sign up: \n");
        printf("   1. input \"username\" and \"password\"\n");
        printf("   2. \"username\" should not exceed 16 characters\n");
        printf("   3. \"password\" should not exceed 16 characters\n");
        break;
    case 2:
        printf(">> select mode: \n");
        printf("   1. friend mode:  add new friends or accept/reject add requests\n");
        printf("   2.  chat mode:   chat with your friends\n");
        break;
    case 3:
        printf(">> friend mode: \n");
        printf("   1. add new friends or accept/reject add requests\n");
        printf("   2. friend states: \n");
        printf("      - being state:  these are your friends! let's chat with each other\n");
        printf("      - recv state:   he/she is waiting for your response\n");
        printf("      - send state:   you have added he/she, but haven't received response yet\n");
        break;
    case 4:
        printf(">> chat mode: \n");
        printf("   1. select a friend, type message and send\n");
        printf("   2. to view the chat box, type \"tail -n +1 -f [x]\" in another terminal,\n");
        printf("      [x] is the file \"%s\" in secure_messaging directory\n", CLIENT_CHAT_FILENAME);
        printf("   3. type \"\\quit\" to exit the chat\n");
        printf("   4. message should not exceed 200 characters\n");
        break;
    default:
        printf(">> hi!\n");
        break;
    }
}

static int _sign_in(void)
{
    char buf[256];
    int start_flag = 1;
    int ret;

    buf[0] = PROTOCOL_SIGN_IN;

    while (true) {
        printf("\n");
        if (start_flag) {
            printf(">> username: ");
            start_flag = 0;
        } else {
            printf("   username: ");
        }
        ret = _helper_get_string(&(buf[1]), 65);
        if (ret == 0) {
            strcpy(username, &(buf[1]));
            break;
        } else {
            printf("\n");
            printf("   username should not exceed 16 characters\n");
        }
    }

    while (true) {
        printf("\n");
        printf("   password: ");
        ret = _helper_get_string(&(buf[66]), 65);
        if (ret == 0) {
            break;
        } else {
            printf("\n");
            printf("   password should not exceed 16 characters\n");
        }
    }

    secure_send(channel, buf, 131, 0, key, iv);
        
    ret = secure_recv(channel, buf, 1, 0, key, iv);
    if (ret > 0) {
        if (buf[0] == PROTOCOL_FAIL) {
            return -1;
        } 
    } else {
        printf("\n");
        printf(">> oops, server error\n");
        _pause();
        exit(EXIT_FAILURE);
    }

    return 0;
}

static int _sign_up(void)
{
    char buf[256];
    int start_flag = 1;
    int ret;

    buf[0] = PROTOCOL_SIGN_UP;

    while (true) {
        printf("\n");
        if (start_flag) {
            printf(">> username: ");
            start_flag = 0;
        } else {
            printf("   username: ");
        }
        ret = _helper_get_string(&(buf[1]), 65);
        if (ret == 0) {
            strcpy(username, &(buf[1]));
            break;
        } else {
            printf("\n");
            printf("   username should not exceed 16 characters\n");
        }
    }

    while (true) {
        printf("\n");
        printf("   password: ");
        ret = _helper_get_string(&(buf[66]), 65);
        if (ret == 0) {
            break;
        } else {
            printf("\n");
            printf("   password should not exceed 16 characters\n");
        }
    }

    secure_send(channel, buf, 131, 0, key, iv);
    
    ret = secure_recv(channel, buf, 1, 0, key, iv);
    if (ret > 0) {
        if (buf[0] == PROTOCOL_FAIL) {
            return -1;
        } 
    } else {
        printf("\n");
        printf(">> oops, server error\n");
        _pause();
        exit(EXIT_FAILURE);
    }

    return 0;
}

static int _recv_friendlist(FILE * file)
{
    char buf[128];
    int ret;

    fprintf(file, "\n");
    fprintf(file, "   state   username   \n");

    while (true) {
        ret = secure_recv(channel, buf, 67, 0, key, iv);
        if (ret > 0) {
            if (buf[0] == PROTOCOL_FRIEND_LIST_END) {
                break;
            } else {
                switch (buf[66])
                {
                case TABLE_F_STATE_BEING:
                    fprintf(file, "   [being] %s\n", &(buf[1]));
                    break;
                case TABLE_F_STATE_RECV:
                    if (strcmp(username, &(buf[1])) < 0) {
                        fprintf(file, "   [recv]  %s\n", &(buf[1]));
                    } else {
                        fprintf(file, "   [send]  %s\n", &(buf[1]));
                    }
                    break;
                case TABLE_F_STATE_SEND:
                    if (strcmp(username, &(buf[1])) < 0) {
                        fprintf(file, "   [send]  %s\n", &(buf[1]));
                    } else {
                        fprintf(file, "   [recv]  %s\n", &(buf[1]));
                    }
                    break;
                default:
                    fprintf(file, "   [?]     %s\n", &(buf[1]));
                    break;
                }
            }
        } else {
            printf("\n");
            printf(">> oops, server error\n");
            _pause();
            exit(EXIT_FAILURE);
        }
    }

    return 0;
}

static int _friend_add(void)
{
    char buf[128];
    int start_flag = 1;
    int ret;

    buf[0] = PROTOCOL_FRIEND_ADD;

    while (true) {
        printf("\n");
        if (start_flag) {
            printf(">> username: ");
            start_flag = 0;
        } else {
            printf("   username: ");
        }
        ret = _helper_get_string(&(buf[1]), 65);
        if (ret == 0) {
            break;
        } else {
            printf("\n");
            printf("   username should not exceed 16 characters\n");
        }
    }

    secure_send(channel, buf, 66, 0, key, iv);
        
    ret = secure_recv(channel, buf, 1, 0, key, iv);
    if (ret > 0) {
        if (buf[0] == PROTOCOL_FAIL || buf[0] == PROTOCOL_ERROR) {
            return -1;
        } 
    } else {
        printf("\n");
        printf(">> oops, server error\n");
        _pause();
        exit(EXIT_FAILURE);
    }

    return 0;
}

static int _friend_accept(void)
{
    char buf[128];
    int start_flag = 1;
    int ret;

    buf[0] = PROTOCOL_FRIEND_ACCEPT;

    while (true) {
        printf("\n");
        if (start_flag) {
            printf(">> username: ");
            start_flag = 0;
        } else {
            printf("   username: ");
        }
        ret = _helper_get_string(&(buf[1]), 65);
        if (ret == 0) {
            break;
        } else {
            printf("\n");
            printf("   username should not exceed 16 characters\n");
        }
    }

    secure_send(channel, buf, 66, 0, key, iv);
        
    ret = secure_recv(channel, buf, 1, 0, key, iv);
    if (ret > 0) {
        if (buf[0] == PROTOCOL_FAIL || buf[0] == PROTOCOL_ERROR) {
            return -1;
        } 
    } else {
        printf("\n");
        printf(">> oops, server error\n");
        _pause();
        exit(EXIT_FAILURE);
    }

    return 0;
}

static int _friend_reject(void)
{
    char buf[128];
    int start_flag = 1;
    int ret;

    buf[0] = PROTOCOL_FRIEND_REJECT;

    while (true) {
        printf("\n");
        if (start_flag) {
            printf(">> username: ");
            start_flag = 0;
        } else {
            printf("   username: ");
        }
        ret = _helper_get_string(&(buf[1]), 65);
        if (ret == 0) {
            break;
        } else {
            printf("\n");
            printf("   username should not exceed 16 characters\n");
        }
    }

    secure_send(channel, buf, 66, 0, key, iv);
        
    ret = secure_recv(channel, buf, 1, 0, key, iv);
    if (ret > 0) {
        if (buf[0] == PROTOCOL_FAIL || buf[0] == PROTOCOL_ERROR) {
            return -1;
        } 
    } else {
        printf("\n");
        printf(">> oops, server error\n");
        _pause();
        exit(EXIT_FAILURE);
    }

    return 0;
}

static void _friend(void)
{
    char buf[128];
    int choice;
    int flush_flag = 1;

    buf[0] = PROTOCOL_FRIEND;
    secure_send(channel, buf, 1, 0, key, iv);

    while (true) {
        if (flush_flag) {
            flush_flag = 0;

            _pause();
            _clear();

            _recv_friendlist(stdout);

            printf("\n");
            printf(">> 1. add\n");
            printf("   2. accept\n");
            printf("   3. reject\n");
            printf("   4. help\n");
            printf("   5. back\n");
        }
        printf("\n");
        printf("<< ");

        if (-1 == _helper_get_int(&choice)) {
            printf("\n");
            printf(">> incorrect input\n");
            continue;
        }

        if (choice == 1) {
            flush_flag = 1;
            if (0 == _friend_add()) {
                printf("\n");
                printf(">> add successfully\n");
            } else {
                printf("\n");
                printf(">> fail\n");
            }
        } else if (choice == 2) {
            flush_flag = 1;
            if (0 == _friend_accept()) {
                printf("\n");
                printf(">> accept successfully\n");
            } else {
                printf("\n");
                printf(">> fail\n");
            }
        } else if (choice == 3) {
            flush_flag = 1;
            if (0 == _friend_reject()) {
                printf("\n");
                printf(">> reject successfully\n");
            } else {
                printf("\n");
                printf(">> fail\n");
            }
        } else if (choice == 4) {
            _help(3);
        } else if (choice == 5) {
            buf[0] = PROTOCOL_FINISH;
            secure_send(channel, buf, 66, 0, key, iv);
            break;
        } else {
            printf("\n");
            printf(">> incorrect input\n");
        }
    }
}

static int _recv_messagelist(FILE * file, int history_mode)
{
    char buf[1024];
    char time_string[26];
    char unread[] = "[unread]";
    time_t time;
    char mark;
    int ret;

    while (true) {
        ret = secure_recv(channel, buf, 812, 0, key, iv);
        if (ret > 0) {
            if (buf[0] == PROTOCOL_FINISH) {
                return -1;
            } else if (buf[0] == PROTOCOL_CHAT_LIST_END) {
                break;
            } else {
                if (buf[1] == PROTOCOL_CHAT_LIST_SEND) {
                    mark = '>';
                } else {
                    mark = '<';
                }

                time = (time_t)*((double *)(&(buf[2])));
                ctime_r(&time, time_string);
                time_string[19] = '\0';
                time_string[24] = '\0';

                /** > 1993 Jun 30 21:49:08
                 *      this is a sent message example
                 *  < 1993 Jun 30 21:49:08 [unread]
                 *      this is a received message example
                */
                fprintf(file, "\n%c %s %s %s\n    %s\n", 
                              mark, &(time_string[20]), &(time_string[4]), 
                              (history_mode & (buf[811] == TABLE_M_STATE_UNREAD)) ? unread : "",
                              &(buf[10]));
                fflush(file);
                fdatasync(fileno(file));
            }
        } else {
            printf("\n");
            printf(">> oops, server error\n");
            _pause();
            exit(EXIT_FAILURE);
        }
    }

    return 0;
}

static void * r_thread_routine(void * arg)
{
    FILE * file = fopen(CLIENT_CHAT_FILENAME, "w");
    int ret;

    ret = _recv_messagelist(file, 1);
    if (ret == 0) {
        fprintf(file, "\n");
        fprintf(file, "---------------- history ----------------\n");
        fflush(file);
        fdatasync(fileno(file));

        while (true) {
            ret = _recv_messagelist(file, 0);
            if (ret == -1) {
                break;
            }
        }
    }

    fclose(file);
    
    return NULL;
}

static void * w_thread_routine(void * arg)
{
    struct timeval tv;
    char buf[1024];

    printf("\n");
    printf("------------------------------   note   ------------------------------\n");
    printf("> to view the chat box, type \"tail -n +1 -f [x]\" in another terminal,\n");
    printf("  [x] is the file \"%s\" in secure_messaging directory\n", CLIENT_CHAT_FILENAME);
    printf("> to exit this chat, type \"\\quit\"\n");
    printf("------------------------------   note   ------------------------------\n");

    while (true) {
        printf("\n");
        printf("# ");

        _helper_get_string(&(buf[9]), 801);

        if (strcmp(&(buf[9]), "\\quit") == 0) {
            buf[0] = PROTOCOL_FINISH;
            secure_send(channel, buf, 810, 0, key, iv);
            break;
        }

        buf[0] = PROTOCOL_CHAT_MESSAGE;

        gettimeofday(&tv, NULL);
        *((double *)(&(buf[1]))) = tv.tv_sec + (double)tv.tv_usec / 1000000;

        secure_send(channel, buf, 810, 0, key, iv);
    }

    return NULL;
}

static void _chat_select(void)
{
    char buf[128];
    int start_flag = 1;
    int ret;

    while (true) {
        buf[0] = PROTOCOL_CHAT_SELECT;

        while (true) {
            printf("\n");
            if (start_flag) {
                printf(">> username: ");
                start_flag = 0;
            } else {
                printf("   username: ");
            }
            ret = _helper_get_string(&(buf[1]), 65);
            if (ret == 0) {
                break;
            } else {
                printf("\n");
                printf("   username should not exceed 16 characters\n");
            }
        }

        secure_send(channel, buf, 66, 0, key, iv);
                
        ret = secure_recv(channel, buf, 1, 0, key, iv);
        if (ret > 0) {
            if (buf[0] == PROTOCOL_SUCCEED) {
                break;
            } else {
                start_flag = 1;
                printf("\n");
                printf(">> fail: he/she is not your friend yet\n");
            }
        } else {
            printf("\n");
            printf(">> oops, server error\n");
            _pause();
            exit(EXIT_FAILURE);
        }
    }
}

static void _chat(void)
{
    pthread_t rw_threads[2];
    FILE * file;
    char buf[128];
    int choice;
    int flush_flag = 1;


    buf[0] = PROTOCOL_CHAT;
    secure_send(channel, buf, 1, 0, key, iv);

    file = tmpfile();
    _recv_friendlist(file);

    while (true) {
        if (flush_flag) {
            flush_flag = 0;

            _pause();
            _clear();

            _helper_put_file(file);

            printf("\n");
            printf(">> 1. select\n");
            printf("   2. help\n");
            printf("   3. back\n");
        }
        printf("\n");
        printf("<< ");

        if (-1 == _helper_get_int(&choice)) {
            printf("\n");
            printf(">> incorrect input\n");
            continue;
        }

        if (choice == 1) {
            flush_flag = 1;

            _chat_select();

            printf("\n");
            printf(">> start messaging\n");
            _pause();
            _clear();

            pthread_create(&(rw_threads[0]), NULL, r_thread_routine, NULL);
            pthread_create(&(rw_threads[1]), NULL, w_thread_routine, NULL);
            pthread_join(rw_threads[1], NULL);
            pthread_join(rw_threads[0], NULL);
        } else if (choice == 2) {
            _help(4);
        } else if (choice == 3) {
            buf[0] = PROTOCOL_FINISH;
            secure_send(channel, buf, 66, 0, key, iv);
            break;
        } else {
            printf("\n");
            printf(">> incorrect input\n");
        }
    }
        
    fclose(file);
}

static void start_routine(void)
{
    char buf[256];
    int choice;
    int online = 0;
    int flush_flag = 1;

    secure_client_buildkey(channel, key, iv);
    _clear();
    _welcome();

    while (true) {
        if (flush_flag) {
            flush_flag = 0;

            _pause();
            _clear();

            printf("\n");
            printf(">> 1. sign in\n");
            printf("   2. sign up\n");
            printf("   3. help\n");
            printf("   4. quit\n");
        }
        printf("\n");
        printf("<< ");

        if (-1 == _helper_get_int(&choice)) {
            printf("\n");
            printf(">> incorrect input\n");
            continue;
        }

        if (choice == 1) {
            flush_flag = 1;
            if (0 == _sign_in()) {
                printf("\n");
                printf(">> sign in successfully\n");
                online = 1;
                break;
            } else {
                printf("\n");
                printf(">> fail: incorrect password\n");
            }
        } else if (choice == 2) {
            flush_flag = 1;
            if (0 == _sign_up()) {
                printf("\n");
                printf(">> sign up successfully\n");
                online = 1;
                break;
            } else {
                printf("\n");
                printf(">> fail: username exists\n");
            }
        } else if (choice == 3) {
            _help(1);
        } else if (choice == 4) {
            buf[0] = PROTOCOL_DISCONNECT;
            secure_send(channel, buf, 131, 0, key, iv);
            break;
        } else {
            printf("\n");
            printf(">> incorrect input\n");
        }
    }

    if (online) {
        while (true) {
            if (flush_flag) {
                flush_flag = 0;

                _pause();
                _clear();

                printf("\n");
                printf(">> 1. friend mode\n");
                printf("   2. chat mode\n");
                printf("   3. help\n");
                printf("   4. quit\n");
            }
            printf("\n");
            printf("<< ");

            if (-1 == _helper_get_int(&choice)) {
                printf("\n");
                printf(">> incorrect input\n");
                continue;
            }

            if (choice == 1) {
                flush_flag = 1;
                _friend();
            } else if (choice == 2) {
                flush_flag = 1;
                _chat();
            } else if (choice == 3) {
                _help(2);
            } else if (choice == 4) {
                buf[0] = PROTOCOL_DISCONNECT;
                secure_send(channel, buf, 1, 0, key, iv);
                break;
            } else {
                printf("\n");
                printf(">> incorrect input\n");
            }
        }
    }
}
