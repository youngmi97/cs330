#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_, char ** token_ptr);
static void initd (void *f_name);
static void __do_fork (void *aux);

/* General process initializer for initd and other process. */
static void
process_init (void) {
	struct thread *current = thread_current ();
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t
process_create_initd (const char *file_name) {
	//printf("[process_create_initd] called \n");
	char *fn_copy;
	tid_t tid;
	char *token_ptr;
	char* name;
	struct thread *curr = thread_current();

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, PGSIZE);

	name = strtok_r((char *) file_name, " ", &token_ptr);

	/* Create a new thread to execute FILE_NAME. */
	//printf("[process_create_initd] creating thread to execute initd \n");
	tid = thread_create (name, PRI_DEFAULT, initd, fn_copy);

	
	curr->child_list[curr->childSize] = tid;
    curr->childSize++;


	//printf("[process_create_initd] created tid is: %d \n", tid);
	if (tid == TID_ERROR) {
		//printf("tid ERROR ----- \n");
		palloc_free_page (fn_copy);
	}
		
	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *f_name) {
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif
	
	
	process_init ();
	
	//printf("[initd] calling process_exec \n");
	//printf("[initd] calling from tid: %d \n", thread_current() -> tid);
	if (process_exec (f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t
process_fork (const char *name, struct intr_frame *if_) {
	/* Clone current thread to new thread.*/
	struct thread * curr = thread_current();

	//printf("[process_fork] called by: %d \n", curr->tid);

	curr->passed_frame = if_;

	sema_init(&curr->sema_initialization, 0);
	tid_t thread_created = thread_create (name, PRI_DEFAULT, __do_fork, curr);
	//printf("[process_fork] thread created: %d \n", thread_created);
	sema_down(&curr->sema_initialization);

	return thread_created;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;

	//printf("[duplicate_pte] va input value: %llx \n", va);
	/* 1. TODO: If the parent_page is kernel page, then return immediately. */
	if (is_kernel_vaddr(va))
	{
		// Returning false results in failure --> true instead
		return true;
	}


	/* 2. Resolve VA from the parent's page map level 4. */
	parent_page = pml4_get_page (parent->pml4, va);

	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */

	//shallow copy --> internal pointers point to the same place
	newpage = palloc_get_page (PAL_USER);
	//no pages available
	if(newpage == NULL){
		//printf("[duplicate_pte] newpage is NULL \n");
		palloc_free_page(newpage);
		return true;
	}
	
	
	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
	

	memcpy(newpage, parent_page, PGSIZE);
	writable = is_writable(pte);
	//printf("[duplicate_pte] writable: %d \n", writable);



	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		/* 6. TODO: if fail to insert page, do error handling. */
		//printf("[duplicate_pte] do error handling \n");
		palloc_free_page(newpage);
		return false;
	}
	return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void
__do_fork (void *aux) {
	struct intr_frame if_;
	struct thread *parent = aux;
	struct thread *current = thread_current ();
	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
	struct intr_frame *parent_if;
	
	parent_if = parent->passed_frame;

	bool succ = true;

	//printf("[__do_fork] parent tid: %d \n", parent->tid);
	//printf("[__do_fork] child tid: %d \n", current->tid);

	/* 1. Read the cpu context to local stack. */
	memcpy (&if_, parent_if, sizeof (struct intr_frame));


	/* 2. Duplicate PT */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL)
		goto error;

	process_activate (current);
#ifdef VM
	supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt))
		goto error;
#else
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent))
	{
		//printf("[__do_fork] pml4_for_each result is null\n");
		goto error;
	}
#endif

	/* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent.*/

	
	parent->child_list[parent->childSize] = current->tid;
    parent->childSize++;

	struct file_descriptors *fd_list = parent->file_table;

	struct file *file_copy_ptr = file_duplicate(parent->executable);

	printf("[__do_fork] parent's executable: %llx \n", file_copy_ptr);

	current->file_table = fd_list;
	current->executable = file_copy_ptr;
	current->childSize = 0;
	current->is_exit = false;
	current->return_value = 0;

	if_.R.rax=0;

	sema_up(&parent->sema_initialization);

	process_init ();


	/* Finally, switch to the newly created process. */
	if (succ)
	{
		//printf("[__do_fork] switch to newly created process \n");
		do_iret (&if_);
	}
error:
	//printf("[__do_fork] exiting thread %d \n", thread_current() ->tid);
	thread_exit ();
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int
process_exec (void *f_name) {
	//char *file_name = f_name;

	//printf("[process_exec] f_name: %s \n", f_name);

	char* file_name=palloc_get_page(0);
	if(file_name==NULL)
	{
		printf("[process_exec] file_name is NULL \n");
		return -1;
	}
	
	char *token_ptr = NULL;
	bool success;

	strlcpy(file_name, (char*)f_name, PGSIZE);

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;


	/* We first kill the current context */
	process_cleanup ();

	file_name = strtok_r(file_name, " ", &token_ptr);
	/* And then load the binary */
	success = load (file_name, &_if, &token_ptr);

	/* If load failed, quit. */
	palloc_free_page (file_name);
	if (!success)
	{
		printf("[process_exec] load failed \n");
		return -1;
	}

	palloc_free_page(f_name);
	/* Start switched process. */
	do_iret (&_if);
	NOT_REACHED ();
}


/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int
process_wait (tid_t child_tid UNUSED) {
	/* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
	 * XXX:       to add infinite loop here before
	 * XXX:       implementing the process_wait. */
	struct thread *t = NULL, *cur = thread_current();
	printf("[process_wait] current tid: %d, name: %s \n", cur->tid, cur->name);
	printf("[process_wait] child_tid tid: %d \n", child_tid);

    int i = 0;
    bool is_child = false;

    t = find_thread(child_tid);

        
    for (i = 0; i < cur->childSize; ++i)
    {
        if (child_tid == cur->child_list[i])
        {
            is_child = true;
        }
    }
    
    if (is_child && t != NULL && t->status != THREAD_DYING && t->tid != -1)
    {
		sema_up(&t->sema_remove);
		// Infinite loop until child exits
		while (t->is_exit == false);
        return t->return_value;
    }

    return -1;
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *curr = thread_current ();
	/* TODO: Your code goes here.
	 * TODO: Implement process termination message (see
	 * TODO: project2/process_termination.html).
	 * TODO: We recommend you to implement process resource cleanup here. */

	//printf("[process_exit] called \n");
//	printf("%s: exit(%d)\n", thread_current()->name, thread_current()->status);
    //thread_current()->return_value = thread_current()->status;
	//printf("[process_exit] thread: %d, %s \n", thread_current()->tid, thread_current()->name);

	//process_cleanup();

	if(curr->file_table!=NULL){
		int size=curr->file_table->size;
		for (int i=0; i<size; i++){
//			printf("[close] :%d\n",curr->file_table->size);
			close(curr->file_table->files[i].fd);
		}
	}
	process_cleanup ();
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();
//	printf("[process_cleanup] welcome!\n");
#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
//		printf("[process_cleanup] pml4 is not null\n");
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
//		printf("[cleanup] pml4 as null\n");
		pml4_activate (NULL);
//		printf("[cleanup] pml4 activate\n");
		pml4_destroy (pml4);
//		printf("[cleanup] pml4 destroy\n");
	}
//	printf("[process_cleanup] end\n");
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */

static bool ra_to_stack(struct intr_frame *if_, uintptr_t *rsp)
{
    *rsp -= sizeof (uintptr_t *);
    memset(*rsp, 0, sizeof (uintptr_t *));
	if_->rsp = *rsp;
    return true;
}

static bool word_alignment(uintptr_t *rsp)
{
    unsigned int word_align = 0;

    if ((word_align = (uint8_t) *rsp % 8) != 0)
    {
        *rsp -= word_align;
        memset(*rsp, 0, word_align);
    }

    return true;
}

static bool create_arg_list(struct list *arg_list,
                            struct argument args[],
                            const char * file_name,
                            char **token_ptr)
{
    char *token = NULL;
    int i = 0;
    list_init(arg_list);

    i = 0;
    for (token = (char*) file_name;
         token != NULL;
         token = strtok_r(NULL, " ", token_ptr))
    {

        args[i].arg = token;
        args[i].len = strnlen(token, ARGLEN);
        list_push_back(arg_list, &args[i].elem);
        ++i;
    }

    return true;
}

static bool arg_to_stack(uintptr_t *rsp, struct list *arg_list)
{
    struct list_elem *arg_elem = NULL;
    struct argument *curr_arg = NULL;

    for (arg_elem = list_rbegin(arg_list);
         arg_elem != list_rend(arg_list);
         arg_elem = list_prev(arg_elem))
    {
        curr_arg = list_entry(arg_elem, struct argument, elem);
        *rsp -= curr_arg->len + 1;
        curr_arg->rsp = *rsp;
        memcpy(*rsp, curr_arg->arg, curr_arg->len + 1);
    }

    return true;
}


static bool arg_addr_to_stack(struct intr_frame *if_, uintptr_t *rsp, struct list *arg_list)
{
    struct list_elem *arg_elem = NULL;
    struct argument *curr_arg = NULL;

    *rsp -= sizeof (char *);
    memset(*rsp, 0, sizeof (char *));

    for (arg_elem = list_rbegin(arg_list);
         arg_elem != list_rend(arg_list);
         arg_elem = list_prev(arg_elem))
    {
        curr_arg = list_entry(arg_elem, struct argument, elem);
        *rsp -= sizeof (char*);
        memcpy(*rsp, &curr_arg->rsp, sizeof (char*));
    }

    //point %rsi to the argv[0] address
	if_->R.rsi = *rsp;

    return true;
}




static bool setup_arg( uintptr_t *rsp, struct intr_frame *if_, char **token_ptr, const char * file_name)
{
    struct list arg_list;
    struct argument args[MAX_ARG];


    create_arg_list(&arg_list, args, file_name, token_ptr);
    arg_to_stack(rsp, &arg_list);
    word_alignment(rsp);

    arg_addr_to_stack(if_, rsp, &arg_list);
    int argc = list_size(&arg_list);
	if_->R.rdi = argc;
    ra_to_stack(if_, rsp);
    //hex_dump((int)(*rsp),*rsp,100,true);

    return true;
}




static bool
load (const char *file_name, struct intr_frame *if_, char ** token_ptr) {
	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	//printf("[load] current thread: %d \n", t->tid);
	

	/* Allocate and activate page directory.  */
	// pml4 --> amd's page table
	t->pml4 = pml4_create ();
	if (t->pml4 == NULL)
		goto done;
	process_activate (thread_current ());


	//printf("[load] process_activate \n");

	//printf("[load] calling filesys_open \n");
	/* Open executable file. */
	//printf("[load] file name: %s \n", file_name);
	

	file = filesys_open (file_name);
	if (file == NULL) {
		printf ("load: %s: open failed\n", file_name);
		goto done;
	}

	//printf("[load] file open \n");
	
	//[Project 2] store the executable on the parent thread
	printf("[load] current thread: %d \n", t->tid);
	t->executable = file;
	printf("[load] current thread executable: %llx \n", t->executable);
	//maybe give file ownership to child thread ??

	/* Read and verify executable header. */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}


	//printf("[load] end of file_read \n");

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* Ignore this segment. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;
			case PT_LOAD:
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable))
						goto done;
				}
				else
					goto done;
				break;
		}
	}

	/* Set up stack. */
	//stack setup faile routine has to be called
	if (!setup_stack (if_))
	{
		printf("[load] setup stack failed \n");
		goto done;
	}

	/* TODO: Your code goes here.
	 * TODO: Implement argument passing (see project2/argument_passing.html). */

	//[project 2] Setting up the argument stack here


	enum intr_level old_level = intr_disable();
	success = setup_arg(&if_->rsp, if_, token_ptr, file_name);
	intr_set_level(old_level);

    if (!success)
    {
        printf("load: error in setup_arguments \n");
    }

	/* Start address. */
	if_->rip = ehdr.e_entry;


	//*(int64_t *)(if_->rsp)=NULL;
	//palloc_free_page(file_name);
	//if(success==true) printf("[load] success is true\n");


	//printf("[load] end of load \n");
	return success;
	//printf("[load] argc from if_: %d \n", if_->R.rdi);
	//printf("[load] argv[0] addr from if_: %p \n", if_->R.rsi);
	//printf("[load] rsp value: %p \n", if_->rsp);


	//setup arguments working perfectly !!! 
	//hex_dump((int) if_->rsp, if_->rsp, 200, true);


done:
	/* We arrive here whether the load is successful or not. */
	file_close (file);
//	palloc_free_page(file_name);
	return success;
}
















/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	/*[Note] Looped until assigned amount of bytes and buffer are allocated
	 * or unless memory allocation fails
	 */
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	//printf("in setup_stack FIRST \n");

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else











/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool
lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		void *aux = NULL;
		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
					writable, lazy_load_segment, aux))
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */

	return success;
}
#endif /* VM */
