#include "threadpool.h"
#include <stdlib.h>
#include <stdio.h>

void* mytask(void* arg)
{
    printf("thread %d is working on task %d\n", pthread_self(), *(int*)arg);
    _sleep(1);
    free(arg);
    return NULL;
}

/*
//���Դ���
int main(void)
{
    threadpool_t pool;
    //��ʼ���̳߳أ���������߳�
    threadpool_init(&pool, 3);
    int i;
    //����ʮ������
    for (i = 0; i < 10; i++)
    {
        int* arg = (int*)malloc(sizeof(int));
        *arg = i;
        threadpool_add_task(&pool, mytask, arg);

    }
    threadpool_destroy(&pool);
    return 0;
}
*/