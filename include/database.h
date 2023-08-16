#ifndef _DATABASE_H_
#define _DATABASE_H_

#include <stdint.h>
#include <mysql/mysql.h>

typedef struct result_t {
    uint64_t r;
    unsigned int c;
    MYSQL_ROW * rows;
    MYSQL_RES * _res;
} result_t;

int database_init(void);
int database_thread_init(void);
MYSQL * database_connect(void);
/* create table if not exists "table" ("definition") */
int database_create_table(MYSQL * mysql, const char * table,
                                        const char * definition);
/* insert into "table" ("column") values ("value") */
int database_insert(MYSQL * mysql, const char * table,
                                    const char * column,
                                    const char * value);
/* update "table" set "assignment" "constraint" */
int database_update(MYSQL * mysql, const char * table,
                                    const char * assignment,
                                    const char * constraint);
/* select "column" from "table" "constraint" */
int database_select(MYSQL * mysql, const char * table,
                                    const char * column,
                                    const char * constraint);
result_t * database_get_result(MYSQL * mysql);
void database_free_result(result_t * result);
void database_disconnect(MYSQL * mysql);
void database_thread_finish(void);
void database_finish(void);

#endif
