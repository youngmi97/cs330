#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#define EXIT_SUCCESS 0          /* Successful execution. */
#define EXIT_FAILURE 1          /* Unsuccessful execution. */
#define FD_TABLE_SIZE 256

/* Process identifier. */
typedef int pid_t;

void syscall_init (void);
void exit(int status);

struct file_elem
{
    struct file *file_ptr;
    int fd;
    pid_t owner;
};

struct file_descriptors
{
    struct file_elem files[FD_TABLE_SIZE];
    int size;
};

int add_file(struct file_descriptors * table, struct file*);
struct file* get_file(struct file_descriptors * table, int fd);
pid_t get_file_owner(struct file_descriptors * table, int fd);
struct file* remove_file(struct file_descriptors * table, int fd);


#endif /* userprog/syscall.h */