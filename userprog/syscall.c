#include "userprog/syscall.h"

#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include <console.h>

#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/palloc.h"

#include "filesys/filesys.h"
#include "filesys/file.h"

#include "userprog/gdt.h"
#include "userprog/process.h"

#include "devices/input.h"
#include "intrinsic.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */


/* Read and write data from/to user space */
//static int64_t get_user(const uint8_t *uaddr);
//static bool put_user (uint8_t *udst, uint8_t byte);


static struct lock locker;
static int fd_gl = 3;
static struct file_descriptors fd_list;

/* Local functions */
static void halt(void) NO_RETURN;
static pid_t exec(const char *file);
static bool create(const char *file, unsigned initial_size);
static bool remove(const char *file);
static int open(const char *file);
static int filesize(int fd);
static int read(int fd, void *buffer, unsigned length);
static int write(int fd, const void *buffer, unsigned length);
static void seek(int fd, unsigned position);
static unsigned tell(int fd);
void close(int fd);


void
syscall_init (void) {
	//printf("[syscall_init] called \n");
    

	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

    lock_init(&locker);
    fd_list.size = 0;

    

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.

	//printf ("[syscall_handler] system call!\n");
    
	int system_call_number = f->R.rax;

	//printf ("[syscall_handler] system_call_number: %d\n", system_call_number);
    //printf ("[syscall_handler] first argument: %s\n", (const char *)f->R.rdi);
    //printf ("[syscall_handler] current thread: %d\n", thread_current() -> tid);
    //if (system_call_number == 2)
    //    printf ("[syscall_handler] intr_frame rdi: %s\n", (const char *)f->R.rdi);

	switch (system_call_number)
    {/* Select proper system call */

        case SYS_HALT:
            //printf ("[syscall_handler] called SYS_HALT\n");
            halt();
            break; /* Halt the operating system. */

        case SYS_EXIT:
            //printf ("[syscall_handler] called SYS_EXIT\n");
            //printf ("[syscall_handler] called from: %d\n", thread_current()->tid);
            exit((int) f->R.rdi);
            break; /* Terminate this process. */
        
        case SYS_FORK:
            //printf ("[syscall_handler] called SYS_FORK\n");
            //thread name passed
            thread_current()->file_table = &fd_list;
            f->R.rax = process_fork((const char *) f->R.rdi, f);
            break;

        case SYS_EXEC:
            //printf ("[syscall_handler] called SYS_EXEC\n");
            f->R.rax = exec((const char *) f->R.rdi);
            break; /* Start another process. */

        case SYS_WAIT:
            //printf ("[syscall_handler] called SYS_WAIT\n");
            //printf ("[syscall_handler] called by: %d \n", thread_current()->tid);
            //printf ("[syscall_handler] wait for: %d \n", f->R.rdi);
            f->R.rax= process_wait((tid_t) f->R.rdi);
            break; /* Wait for a child process to die. */

        case SYS_CREATE:
            //printf ("[syscall_handler] called SYS_CREATE\n");
            f->R.rax = create((const char *) f->R.rdi,
                                   (unsigned) f->R.rsi);
            break; /* Create a file. */

        case SYS_REMOVE:
            //printf ("[syscall_handler] called SYS_REMOVE\n");
            f->R.rax = remove((const char *) f->R.rdi);
            break; /* Delete a file. */

        case SYS_OPEN:
            //printf ("[syscall_handler] called SYS_OPEN \n");
            f->R.rax = open((const char *) f->R.rdi);
            break; /* Open a file. */

        case SYS_FILESIZE:
            //printf ("[syscall_handler] called SYS_FILESIZE\n");
            f->R.rax = filesize((int) f->R.rdi);
            break; /* Obtain a file's size. */

        case SYS_READ:
            //printf ("[syscall_handler] called SYS_READ\n");
            f->R.rax = read((int) f->R.rdi,
                                 (void*) f->R.rsi,
                                 (unsigned) f->R.rdx);
            break; /* Read from a file. */

        case SYS_WRITE:
            //printf ("[syscall_handler] called SYS_WRITE\n");
            f->R.rax = write( f->R.rdi,
                                  (void*) f->R.rsi,
                                  (unsigned) f->R.rdx);
            break; /* Write to a file. */

        case SYS_SEEK:
            //printf ("[syscall_handler]called SYS_SEEK\n");
            seek((int) f->R.rdi, (unsigned) f->R.rsi);
            break; /* Change position in a file. */

        case SYS_TELL:
            //printf ("[syscall_handler]called SYS_TELL\n");
            f->R.rax = tell((int) f->R.rdi);
            break; /* Report current position in a file. */

        case SYS_CLOSE:
            //printf ("[syscall_handler] called SYS_CLOSE\n");
            close((int) f->R.rdi);
            break; /* Close a file. */
    }

	//thread_exit ();
}



/*
 * SYSCALL HANDLING FUNCTIONS
 */

static pid_t exec(const char *cmd_line)
{

    int retVal = -1;
    
    if (cmd_line != NULL)
    {
        char *exec_page = palloc_get_page(0);
		strlcpy (exec_page, cmd_line, PGSIZE);
        retVal = process_exec(exec_page);
    }

    return retVal;
}

static void halt(void)
{
    power_off();
}


/*
 * Process Termination Message
 */

void exit(int status)
{
    printf("%s: exit(%d)\n", thread_current()->name, status);
    thread_current()->return_value = status;
    //sema_up(&thread_current()->sema_wait);
    //printf("[process_exit] file table size: %d \n", thread_current()->file_table->size);
    thread_exit();
}

static bool remove(const char *file)
{
    bool ret;

    lock_acquire(&locker);

    if (!is_user_vaddr(file))
    {
        lock_release(&locker);
        exit(-1);
    }

    ret = filesys_remove(file);

    lock_release(&locker);

    return ret;
}

static int open(const char *file)
{
    struct file * file_ptr = NULL;
    int fd = -1;

    //printf("[open] called \n");


    lock_acquire(&locker);

    if (!is_user_vaddr(file) || file == NULL)
    {
        lock_release(&locker);
        //printf("[open] file not in user vaddr \n");
        exit(-1);
    }

    file_ptr = filesys_open(file);
    if (file_ptr == NULL)
    {
        lock_release(&locker);
        //printf("[open] file_ptr is NULL \n");
        return -1;
    }
    
    if(strcmp(thread_current()->name, file)==0) 
    {
        printf("[open] thread name equals file name\n");
        file_deny_write(file_ptr);
    }
    fd = add_file(&fd_list, file_ptr);
    lock_release(&locker);

    return fd;
}

void close(int fd)
{
    struct file *file_ptr = NULL;
    struct thread *curr = thread_current();

    lock_acquire(&locker);

    file_ptr = get_file(&fd_list, fd);

    if (file_ptr != NULL)
    {

        //have to remove_file only when it is not a child process
        if(curr->childSize != 0)
        {
//	   printf("[close] size before %d\n", fd_list.size); 
            file_close(file_ptr);
            remove_file(&fd_list, fd);
//	   printf("[close] size after %d\n", fd_list.size);
        }
    }

    lock_release(&locker);
}

static int read(int fd, void *buffer, unsigned length)
{
    //printf("[read] fd input: %d \n", fd);
    //printf("[read]input length requested: %d \n", length);
    //printf("[read] called by tid: %d \n", thread_current()->tid);
    struct thread *curr = thread_current();
    int retVal = -1;
    unsigned int counterForLoop;
    struct file* file_ptr = NULL;
//    if(!is_user_vaddr(buffer)) exit(-1);

    lock_acquire(&locker);

    if (fd == STDIN_FILENO)
    {
        for (counterForLoop = 0;
             counterForLoop != length;
             ++counterForLoop)
        {
            *(uint8_t*) (buffer + counterForLoop) = input_getc();
        }
        retVal = length;
    }
    else if (fd == STDOUT_FILENO)
    {
        retVal = -1;
    }
    else
    {
        if (!is_user_vaddr(buffer + length))
        {
            lock_release(&locker);
            exit(-1);
        }
        else
        {
            file_ptr = get_file(&fd_list, fd);

            if (file_ptr != NULL)
            {
                retVal = file_read(file_ptr, buffer, length);


                if (curr->tid !=  get_file_owner(&fd_list, fd))
                    file_ptr->pos -= (off_t) retVal;
            }
            else
            {
                retVal = -1;
            }
        }
    }

    lock_release(&locker);

    return retVal;

}

static int write(int fd, const void *buffer, unsigned size)
{
    struct file *file_ptr = NULL;
    int retVal = -1;

    lock_acquire(&locker);

    if (fd == STDOUT_FILENO)
    {
        putbuf(buffer, size);
        retVal = size;
    }
    else if (fd == STDIN_FILENO)
    {
        retVal = -1;
    }
    else
    {

        if (!is_user_vaddr(buffer + size))
        {
            lock_release(&locker);
            exit(-1);
        }
        else
        {
            file_ptr = get_file(&fd_list, fd);

            if (file_ptr != NULL)
            {
                retVal = file_write(file_ptr, buffer, size);
            }
            else
            {
                retVal = 0;
            }

        }

    }

    lock_release(&locker);
    return retVal;
}

static bool create(const char *file, unsigned initial_size)
{

    lock_acquire(&locker);

    if (file == NULL || !is_user_vaddr(file) )
    {
        lock_release(&locker);
        exit(-1);
    }
    
    bool status = filesys_create(file, initial_size);

    lock_release(&locker);
    return status;
}

static int filesize(int fd)
{
    int size = 0;
    struct file *file_ptr = NULL;

    lock_acquire(&locker);

    file_ptr = get_file(&fd_list, fd);

    if (file_ptr != NULL)
    {
        size = file_length(file_ptr);
    }

    lock_release(&locker);
    return size;
}

static void seek(int fd, unsigned position)
{
    struct file *file_ptr = NULL;

    lock_acquire(&locker);
    
    file_ptr = get_file(&fd_list, fd);

    if (file_ptr != NULL)
    {
        file_seek(file_ptr, position);
    }

    lock_release(&locker);
}

static unsigned tell(int fd)
{
    struct file *file_ptr = NULL;
    unsigned int tell = 0;

    lock_acquire(&locker);

    file_ptr = get_file(&fd_list, fd);

    if (file_ptr != NULL)
    {
        tell = file_tell(file_ptr);
    }

    lock_release(&locker);
    return tell;
}



//[Project 2] FILE HANDLING

int add_file(struct file_descriptors *table, struct file* file_ptr)
{
    //printf("[add_file] called\n");
    int size = table->size;
    struct file_elem file_el;
    struct thread * curr = thread_current();

    /* Allocate fd and set datas */
    fd_gl++;
    file_el.fd = fd_gl;
    file_el.file_ptr = file_ptr;
    file_el.owner = curr->tid;

    /* Add to table */
    table->files[size] = file_el;
    table->size++;

    //printf("table size: %d \n", table->size);

    return file_el.fd;
}

struct file* get_file(struct file_descriptors * table, int fd)
{
    int i = 0;
    int size = table->size;

    //printf("table size: %d \n", size);

    for (i = 0; i < size; ++i)
    {
        //printf("[get_file] fd in fd_list: %d \n", table->files[i].fd);
        if (table->files[i].fd == fd)
        {
            return table->files[i].file_ptr;
        }
    }
    return NULL;
}

pid_t get_file_owner(struct file_descriptors * table, int fd)
{
    int i = 0;
    int size = table->size;

    for (i = 0; i < size; ++i)
    {
        if (table->files[i].fd == fd)
        {
            return table->files[i].owner;
        }
    }
    return -1;
}

struct file* remove_file(struct file_descriptors * table, int fd)
{
    int i = 0;
    int j = 0;
    int size = table->size;
    struct file * file_ptr;

    for (i = 0; i < size; ++i)
    {
        if (table->files[i].fd == fd)
        {
            file_ptr = table->files[i].file_ptr;
            for (j = i; j < size - 1; ++j)
            {
                table->files[j] = table->files[j + 1];
            }
            table->size--;
            return file_ptr;
        }
    }
    return NULL;
}
