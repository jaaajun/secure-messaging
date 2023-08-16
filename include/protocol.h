#ifndef _PROTOCOL_H_
#define _PROTOCOL_H_

/**
 * database organization:
 *      (u): "user" table
 *          username    varchar(64) character set utf8mb4 not null  <- (primary key)
 *          password    varchar(64) character set utf8mb4 not null
 *      (f): "friend" table
 *          username1   varchar(64) character set utf8mb4 not null  <- (primary key)
 *          username2   varchar(64) character set utf8mb4 not null  <- (primary key)
 *          state       tinyint not null
 *      (m): "message" table
 *          id          bigint not null auto_increment              <- (primary key)
 *          username1   varchar(64) character set utf8mb4 not null  <- (send)
 *          username2   varchar(64) character set utf8mb4 not null  <- (recv)
 *          time        double not null
 *          content     varchar(800) character set utf8mb4
 *          state       tinyint not null
 */

#undef  MULTICORE

#define SERVER_IP                   "xxx"
#define SERVER_PORT                 25566
#define SERVER_MAX_CLIENT_NUM       10
#define SERVER_CHAT_SYN_INTERVAL    0.5

#define CLIENT_CHAT_FILENAME        "secure_messaging.chat"

#define LOG_USE_STDOUT
#define LOG_FILENAME                "xxx"

#define DATABASE_HOST               "localhost"
#define DATABASE_USER               "xxx"
#define DATABASE_PASSWORD           "xxx"
#define DATABASE_DBNAME             "secure_messaging_db"

#define TABLE_F_STATE_BEING         0x01
#define TABLE_F_STATE_RECV          0x02
#define TABLE_F_STATE_RECV_REJ      0x04
#define TABLE_F_STATE_SEND          0x08
#define TABLE_F_STATE_SEND_REJ      0x10
#define TABLE_F_STATE_NULL          0x7F

#define TABLE_M_STATE_READ          0x01
#define TABLE_M_STATE_UNREAD        0x02

#define PROTOCOL_BUILD_P            0x00    /* flag + 512B dh_p */
#define PROTOCOL_BUILD_PUBK         0x01    /* flag + 512B dh_pubk */

#define PROTOCOL_SIGN_IN            0x10    /* flag + 65B username + 65B password */
#define PROTOCOL_SIGN_UP            0x11    /* flag + 65B username + 65B password */

#define PROTOCOL_CHAT               0x20    /* flag */
#define PROTOCOL_CHAT_SELECT        0x21    /* flag + 65B username */
#define PROTOCOL_CHAT_MESSAGE       0x22    /* flag + 8B time + 801B message */
#define PROTOCOL_CHAT_LIST_SEND     0x2C    /* flag */
#define PROTOCOL_CHAT_LIST_RECV     0x2D    /* flag */
#define PROTOCOL_CHAT_LIST          0x2E    /* flag + 1B sr_flag + 8B time + 801B message + 1B state */
#define PROTOCOL_CHAT_LIST_END      0x2F    /* flag + 811B null */

#define PROTOCOL_FRIEND             0x30    /* flag */
#define PROTOCOL_FRIEND_ADD         0x31    /* flag + 65B username */
#define PROTOCOL_FRIEND_ACCEPT      0x32    /* flag + 65B username */
#define PROTOCOL_FRIEND_REJECT      0x33    /* flag + 65B username */
#define PROTOCOL_FRIEND_LIST        0x3E    /* flag + 65B username + 1B state */
#define PROTOCOL_FRIEND_LIST_END    0x3F    /* flag + 66B null */

#define PROTOCOL_ERROR              0x7B    /* flag */
#define PROTOCOL_FAIL               0x7C    /* flag */
#define PROTOCOL_SUCCEED            0x7D    /* flag */
#define PROTOCOL_FINISH             0x7E    /* flag */
#define PROTOCOL_DISCONNECT         0x7F    /* flag */

#endif
