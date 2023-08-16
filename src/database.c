#include "protocol.h"
#include "database.h"
#include <mysql/mysql.h>
#include <stdio.h>
#include <stdlib.h>

static int _command_check(const char * command)
{
    /* todo */
    return 0;
}

int database_init(void)
{
    return mysql_library_init(0, NULL, NULL);
}

int database_thread_init(void)
{
    return mysql_thread_init();
}

MYSQL * database_connect(void)
{
    MYSQL * mysql;

    mysql = mysql_init(NULL);
    if (mysql != NULL)
    {
        if (NULL == mysql_real_connect(mysql, DATABASE_HOST, 
                                            DATABASE_USER,
                                            DATABASE_PASSWORD, 
                                            DATABASE_DBNAME,
                                            0, NULL, 0))
        {
            mysql_close(mysql);
            mysql = NULL;
        }
    }

    return mysql;
}

int database_create_table(MYSQL * mysql, const char * table,
                                        const char * definition)
{
    char command[1024];

    if (1024 <= snprintf(command, 1024, "create table if not exists %s (%s)", 
                                        table, definition))
        return -2;
    if (_command_check(command) != 0)
        return -1;

    return mysql_query(mysql, command);
}

int database_insert(MYSQL * mysql, const char * table,
                                    const char * column,
                                    const char * value)
{
    char command[1024];

    if (1024 <= snprintf(command, 1024, "insert into %s (%s) values (%s)", 
                                        table, column, value))
        return -2;
    if (_command_check(command) != 0)
        return -1;

    return mysql_query(mysql, command);
}

int database_update(MYSQL * mysql, const char * table,
                                    const char * assignment,
                                    const char * constraint)
{
    char command[1024];

    if (1024 <= snprintf(command, 1024, "update %s set %s %s", 
                                        table, assignment, constraint))
        return -2;
    if (_command_check(command) != 0)
        return -1;

    return mysql_query(mysql, command);
}

int database_select(MYSQL * mysql, const char * table,
                                    const char * column,
                                    const char * constraint)
{
    char command[1024];

    if (1024 <= snprintf(command, 1024, "select %s from %s %s", 
                                        column, table, constraint))
        return -2;
    if (_command_check(command) != 0)
        return -1;

    return mysql_query(mysql, command);
}

result_t * database_get_result(MYSQL * mysql)
{
    result_t * res;

    res = (result_t *)malloc(sizeof(result_t));

    res->_res = mysql_store_result(mysql);
    res->c = mysql_field_count(mysql);
    if (res->_res == NULL) {
        res->r = 0;
        res->rows = NULL;
    } else {
        res->r = mysql_num_rows(res->_res);
        res->rows = (MYSQL_ROW *)malloc(sizeof(MYSQL_ROW) * res->r);
        for (int i = 0; i < res->r; ++i) {
            res->rows[i] = mysql_fetch_row(res->_res);
        }
    }

    return res;
}

void database_free_result(result_t * result)
{
    free(result->rows);
    mysql_free_result(result->_res);
    free(result);
}

void database_disconnect(MYSQL * mysql)
{
    mysql_close(mysql);
}

void database_thread_finish(void)
{
    mysql_thread_end();
}

void database_finish(void)
{
    mysql_library_end();
}
