#ifndef _UTILITY_H_
#define _UTILITY_H_

#include <pthread.h>

struct queue
{
    pthread_mutex_t lock;
    int front;
    int rear;
    int cur_size;
    int max_size;
    void ** data;
};

struct queue * queue_init(int size);
int enqueue(struct queue * q, void * data);
void * dequeue(struct queue * q);
void queue_finish(struct queue * q);

#endif