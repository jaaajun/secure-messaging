#include "protocol.h"
#include "queue.h"
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>

struct queue * queue_init(int size)
{
    struct queue * q;

    q = (struct queue *)malloc(sizeof(struct queue));
    if (q != NULL) {
        pthread_mutex_init(&(q->lock), NULL);
        q->front = 0;
        q->rear = -1;
        q->cur_size = 0;
        q->max_size = size;
        q->data = (void **)malloc(size * sizeof(void *));
        if (q->data == NULL) {
            pthread_mutex_destroy(&(q->lock));
            free(q);
            q = NULL;
        }
    }

    return q;
}

int enqueue(struct queue * q, void * data)
{
    int ret;

#ifdef MULTICORE
    while (pthread_mutex_trylock(&(q->lock))) {
        if (errno != EBUSY) { return -2; }
    }
#else
    pthread_mutex_lock(&(q->lock));
#endif /* MULTICORE */

    if (q->cur_size == q->max_size)
        ret = -1;
    else
    {
        q->rear = (q->rear + 1) % q->max_size;
        q->data[q->rear] = data;
        (q->cur_size)++;
        ret = 0;
    }

    pthread_mutex_unlock(&(q->lock));

    return ret;
}

void * dequeue(struct queue * q)
{
    void * ret;

#ifdef MULTICORE
    while (pthread_mutex_trylock(&(q->lock))) {
        if (errno != EBUSY) { return NULL; }
    }
#else
    pthread_mutex_lock(&(q->lock));
#endif /* MULTICORE */

    if (q->cur_size == 0)
        ret = NULL;
    else
    {
        ret = q->data[q->front];
        q->front = (q->front + 1) % q->max_size;
        (q->cur_size)--;
    }

    pthread_mutex_unlock(&(q->lock));

    return ret;
}

void queue_finish(struct queue * q)
{
    free(q->data);
    pthread_mutex_destroy(&(q->lock));
    free(q);
}
