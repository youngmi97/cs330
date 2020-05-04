#include "userprog/syscall.h"

#include <stdio.h>
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

#include "filesys/filesys.h"
#include "filesys/file.h"

#include "userprog/gdt.h"
#include "userprog/process.h"

#include "devices/input.h"
#include "intrinsic.h"


static struct lock locker;
static int fd_gl = 3;
static struct fd_table fd_list;

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

static uint64_t fetch_argument(uintptr_t rsp, unsigned int arg_num);

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
static uint64_t get_user_word(const uint64_t *uaddr);
static int64_t get_user(const uint8_t *uaddr);
//static bool put_user (uint8_t *udst, uint8_t byte);


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
static void close(int fd);

void
syscall_init (void) {
	printf("[syscall_init] called \n");
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	lock_init(&locker);
    init_fd_table(&fd_list);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	printf ("[syscall_handler] system call!\n");
	int system_call_number = fetch_argument(f->rsp, 0);

	printf ("[syscall_handler] system_call_number: %d\n", system_call_number);


	 switch (system_call_number)
    {/* Select proper system call */

        case SYS_HALT:
            halt();
            break; /* Halt the operating system. */

        case SYS_EXIT:
            exit((int) fetch_argument(f->rsp, 1));
            break; /* Terminate this process. */

        case SYS_EXEC:
            f->R.rax = exec((const char *) fetch_argument(f->rsp, 1));
            break; /* Start another process. */

        case SYS_WAIT:
            f->R.rax= process_wait((tid_t) fetch_argument(f->rsp, 1));
            break; /* Wait for a child process to die. */

        case SYS_CREATE:
            f->R.rax = create((const char *) fetch_argument(f->rsp, 1),
                                   (unsigned) fetch_argument(f->rsp, 2));
            break; /* Create a file. */

        case SYS_REMOVE:
            f->R.rax = remove((const char *) fetch_argument(f->rsp, 1));
            break; /* Delete a file. */

        case SYS_OPEN:
            f->R.rax = open((const char *) fetch_argument(f->rsp, 1));
            break; /* Open a file. */

        case SYS_FILESIZE:
            f->R.rax = filesize((int) fetch_argument(f->rsp, 1));
            break; /* Obtain a file's size. */

        case SYS_READ:
            f->R.rax = read((int) fetch_argument(f->rsp, 1),
                                 (void*) fetch_argument(f->rsp, 2),
                                 (unsigned) fetch_argument(f->rsp, 3));
            break; /* Read from a file. */

        case SYS_WRITE:
            f->R.rax = write( fetch_argument(f->rsp, 1),
                                  (void*) fetch_argument(f->rsp, 2),
                                  (unsigned) fetch_argument(f->rsp, 3));
            break; /* Write to a file. */

        case SYS_SEEK:
            seek((int) fetch_argument(f->rsp, 1), (unsigned) fetch_argument(f->rsp, 2));
            break; /* Change position in a file. */

        case SYS_TELL:
            f->R.rax = tell((int) fetch_argument(f->rsp, 1));
            break; /* Report current position in a file. */

        case SYS_CLOSE:
            close((int) fetch_argument(f->rsp, 1));
            break; /* Close a file. */
    }

	//thread_exit ();
}



/* Writes BYTE to user address UDST.
 * UDST must be below KERN_BASE.
 * Returns true if successful, false if a segfault occurred. */
/* static bool
put_user (uint8_t *udst, uint8_t byte) {
    int error_code;
    asm ("movl $1f, %0; movb %b2, %1; 1:"
    : "=&a" (error_code), "=m" (*udst) : "q" (byte));
    return error_code != -1;
} */

/*
 * SYSCALL HANDLING FUNCTIONS
 */

static pid_t exec(const char *file)
{
    int retVal = -1;

    lock_acquire(&locker);
    
    if (file != NULL && is_user_vaddr(file))
    {
        retVal = process_create_initd(file);
    }
    lock_release(&locker);

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
    struct file * file_ptr = NULL; /* opened file by filesys_open */
    int fd = -1;

    lock_acquire(&locker);

    if (!is_user_vaddr(file))
    {
        lock_release(&locker);
        exit(-1);
    }

    filesys_create(file, 500);

    file_ptr = filesys_open(file);

    if (file_ptr != NULL)
    {
        fd = add_file(&fd_list, file_ptr);
    }

    //printf("\nOpen %s, fd:%d, owner :%d , lsize:%d\n", file, fd, get_file_owner(&fd_list, fd), fd_list.size);

    lock_release(&locker);

    return fd;
}

static void close(int fd)
{
    struct file *file_ptr = NULL;

    lock_acquire(&locker);

    file_ptr = get_file(&fd_list, fd);

    //printf("\nClose, fd:%d , in list %p, owner:%d , lsize:%d\n", fd, file_ptr, get_file_owner(&fd_list, fd), fd_list.size);

    if (file_ptr != NULL)
    {
        file_close(file_ptr);
        remove_file(&fd_list, fd);
    }

    lock_release(&locker);
}

static int read(int fd, void *buffer, unsigned length)
{
    int retVal = -1;
    unsigned int counterForLoop;
    struct file* file_ptr = NULL;

    lock_acquire(&locker);

    if (fd == STDIN_FILENO/*SDTIN_FILENO*/)
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
            {/* If file is valid and pointers are in user space(means valid ptr) */
                retVal = file_read(file_ptr, buffer, length);
            }
            else
            {
                retVal = -1;
            }

            //printf("\nRead, fd:%d , in list : %p , ret:%d, lsize:%d\n", fd, file_ptr, retVal, fd_list.size);
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
    {// If the process has open file,and want to write it.

        if (!is_user_vaddr(buffer + size))
        {
            lock_release(&locker);
            exit(-1);
        }
        else
        {
            file_ptr = get_file(&fd_list, fd);

            if (file_ptr != NULL)
            {/* If file is valid and pointers are in user space(means valid ptr) */
                retVal = file_write(file_ptr, buffer, size);
            }
            else
            {// Error 
                retVal = 0;
            }

           // printf("\nWrite, fd:%d , in list :%p , ret:%d , owner:%d ,lsize:%d\n", fd, file_ptr, retVal, thread_current()->tid, fd_list.size);

        }

    }

    lock_release(&locker);
    return retVal;
}

static bool create(const char *file, unsigned initial_size)
{
    bool status;

    lock_acquire(&locker);
    
    if (!is_user_vaddr(file))
    {
        lock_release(&locker);
        exit(-1);
    }
    
    status = filesys_create(file, initial_size);

    //printf("\n[ '%s' , init_size: %d create stat:%d]\n",file,initial_size,status);

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




/*
 * Returns integer from stack
 */
 static uint64_t
 fetch_argument(uintptr_t rsp, unsigned int arg_num)
{
	printf("[fetch_argument] got rsp value: %p \n", rsp);
    const uint64_t *uaddr = &rsp + arg_num * 4;
	printf("[fetch_argument] got uaddr value: %p \n", *uaddr);
    if (!is_user_vaddr(uaddr))
    {
		printf("[fetch_argument] not user vaddr \n");
        exit(EXIT_FAILURE);
    }

    return get_user_word(uaddr);
}

/*
 * Gets 8bytes from user memory space begining adress uaddr
 */
static uint64_t
get_user_word(const uint64_t *uaddr)
{
    int lsb, msb, sec, thrd;

    lsb = get_user((uint8_t *)uaddr);
    sec = get_user((uint8_t *)uaddr + 1) << 8;
    thrd = get_user((uint8_t *)uaddr + 2) << 16;
    msb = get_user((uint8_t *)uaddr + 3) << 24;

    return msb + thrd + sec + lsb;
}


/* Reads a byte at user virtual address UADDR.
 * UADDR must be below KERN_BASE.
 * Returns the byte value if successful, -1 if a segfault
 * occurred. */
static int64_t
get_user (const uint8_t *uaddr) {
    int64_t result;
	if (!is_user_vaddr(uaddr))
        exit(EXIT_FAILURE);
    __asm __volatile (
	"movabsq $done_get, %0\n"
	"movzbq %1, %0\n"
	"done_get:\n"
	: "=&a" (result) : "m" (*uaddr));
    return result;
}








void init_fd_table(struct fd_table* table)
{
    table->size = 0;
}

int add_file(struct fd_table *table, struct file* file_ptr)
{
    int size = table->size;
    struct file_element file_el;
    struct thread * thr = thread_current();

    /* Allocate fd and set datas */
    fd_gl++;
    file_el.fd = fd_gl;
    file_el.file_ptr = file_ptr;
    file_el.owner = thr->tid;

    /* Add to table */
    table->files[size] = file_el;
    table->size++;

    return file_el.fd;
}

struct file* get_file(struct fd_table * table, int fd)
{
    int i = 0;
    int size = table->size;

    for (i = 0; i < size; ++i)
    {
        if (table->files[i].fd == fd)
        {
            return table->files[i].file_ptr;
        }
    }
    return NULL;
}

pid_t get_file_owner(struct fd_table * table, int fd)
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

struct file* remove_file(struct fd_table * table, int fd)
{
    int i = 0;
    int j = 0;
    int size = table->size;
    struct file * file_ptr;

    for (i = 0; i < size; ++i)
    {
        if (table->files[i].fd == fd)
        {/* If found, shift elements and return file * */
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