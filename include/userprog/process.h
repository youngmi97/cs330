#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"


#define ARGLEN 30
#define MAX_ARG 128 

struct argument
{
    char *arg; /* Argument(which is a string) pointer */
    size_t len; /* Length of the argument */
    void *rsp; /* Address of the argument in stack */
    struct list_elem elem; /* for listing */
};



tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);

#endif /* userprog/process.h */
