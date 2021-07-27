#ifndef _CONDITION_H_
#define _CONDITION_H_


#include "pthreads_x64-windows/include/pthread.h"
#pragma comment(lib, "pthreads_x64-windows/lib/pthreadVC3.lib")
#pragma comment(lib, "pthreads_x64-windows/lib/pthreadVCE3.lib")
#pragma comment(lib, "pthreads_x64-windows/lib/pthreadVSE3.lib")
//��װһ��������������������Ϊ״̬
typedef struct condition
{
    pthread_mutex_t pmutex;
    pthread_cond_t pcond;
}condition_t;

//��״̬�Ĳ�������
int condition_init(condition_t* cond);
int condition_lock(condition_t* cond);
int condition_unlock(condition_t* cond);
int condition_wait(condition_t* cond);
int condition_timedwait(condition_t* cond, const struct timespec* abstime);
int condition_signal(condition_t* cond);
int condition_broadcast(condition_t* cond);
int condition_destroy(condition_t* cond);

#endif