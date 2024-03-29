#include "protocol.h"
#include "log.h"
#include <stdio.h>
#include <pthread.h>
#include <sys/time.h>
#include <stdarg.h>
#include <errno.h>

static pthread_mutex_t log_mutex;
static FILE * log_file;

int log_init(void)
{
#ifdef LOG_USE_STDOUT
    log_file = stdout;
#else
    log_file = fopen(LOG_FILENAME, "w");
    if (log_file == NULL)
        return -1;
#endif /* LOG_USE_STDOUT */
    pthread_mutex_init(&log_mutex, NULL);

    return 0;
}

int log_print(int type, const char msg[], ...)
{
    struct timeval tv;
    va_list args;

#ifdef MULTICORE
    while (pthread_mutex_trylock(&log_mutex)) {
        if (errno != EBUSY) { return -1; }
    }
#else
    pthread_mutex_lock(&log_mutex);
#endif /* MULTICORE */

    gettimeofday(&tv, NULL);

    /**
     * format:
     *   [time][type]message
    */
    fprintf(log_file, "[%lf]", tv.tv_sec + (double)tv.tv_usec / 1000000);
    switch (type)
    {
    case LOG_INFO:
        fprintf(log_file, "[INFO]");
        break;
    case LOG_WARNING:
        fprintf(log_file, "[WARNING]");
        break;
    case LOG_ERROR:
        fprintf(log_file, "[ERROR]");
        break;
    default:
        fprintf(log_file, "[UNKNOWN]");
        break;
    }
    va_start(args, msg);
    vfprintf(log_file, msg, args);
    va_end(args);
    fprintf(log_file, "\n");

    pthread_mutex_unlock(&log_mutex);

    fflush(log_file);

    return 0;
}

void log_finish(void)
{
    pthread_mutex_destroy(&log_mutex);
#ifdef LOG_USE_STDOUT
    /* do nothing */
#else
    fclose(log_file);
#endif /* LOG_USE_STDOUT */
}
