/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include <hash.h>

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */

		/* TODO: Insert the page into the spt. */
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function. */
	struct hash_elem* hash_elem = NULL;
	page->va = va;

	hash_elem = hash_find(spt, &page->elem);

	if (hash_elem != NULL)
	{
		page = hash_entry(hash_elem, struct page, elem);
	}

	return page;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	int succ = false;
	/* TODO: Fill this function. */
	if (page != NULL)
	{
		// Have to check that va doesnt exist in the spt->page_table
		if (hash_insert(&spt->page_table, &page->elem) == NULL)
		{
			succ = true;
			return succ;
		}

	}

	// Such page already exists
	free(page);
	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}


/* Initialize Frame Table */
static struct hash frame_table;
static struct lock locker;

void initialize_frame_table(void)
{
    hash_init(&frame_table, frame_hash, frame_hash_less,NULL);    
    lock_init(&locker);
}



/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	/* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */
	struct hash_iterator i;
	struct thread* thread = NULL;
	struct page* page = NULL;

	lock_acquire(&locker);

	if (!hash_empty(&frame_table))
	{
		// Get the first element from the frame_table
		hash_first(&i, &frame_table);
		hash_next(&i);
		struct frame* frame = hash_entry(hash_cur(&i), struct frame, elem);


		// Check if the page is dirty
		thread = frame->thread;
		page = frame->page;
		if (!pml4_is_dirty(thread->pml4, page))
		{
			/* Not sure if evicting on this criteria is correct ...*/
			/* Maybe get frame to be evicted from vm_get_victim
			 * and do actual eviction here */
			
			// Free up resources for the victim frame and return pointer to it?
			hash_delete(&frame_table, &frame->elem);
			return frame->frame_ptr;
		}

	}
	lock_release(&locker);

	return NULL;
}



/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = NULL;
	
	/* TODO: Fill this function. */
	struct frame* new_frame;
	lock_acquire(&locker);

	while(new_frame == NULL)
	{
		frame = malloc(sizeof(struct frame)); 
		new_frame = palloc_get_page(PAL_USER);

		if (new_frame != NULL)
		{
			/* Initialize Frame Data*/
			frame->thread = thread_current();
			frame->frame_ptr = new_frame;
			frame->order = hash_size(&frame_table);
			hash_insert(&frame_table,&frame->elem);
		}

		else
		{
			vm_evict_frame();
		}
	}
	lock_release(&locker);

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */

	return vm_do_claim_page (page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function */
	page = spt_find_page(&thread_current()->spt, va);
	if (page == NULL)
		return false;

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->writable);
	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) 
{
	hash_init(spt->page_table, page_hash, page_hash_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	 // What is storage here?
}






/*[Project 3] Hash structure related helper functions */
unsigned page_hash(struct hash_elem* e, void* aux UNUSED)
{
    struct page* page = hash_entry(e, struct page, elem);
    return hash_int((int) page->va);
}

bool page_hash_less(struct hash_elem* a, struct hash_elem* b, void* aux UNUSED)
{
    struct page* page_a = hash_entry(a, struct page, elem);
    struct page* page_b = hash_entry(b, struct page, elem);

    return page_a->va < page_b->va;
}

unsigned frame_hash (struct hash_elem* e, void* aux UNUSED)
{
   struct frame* frame = hash_entry(e, struct frame, elem);
   return hash_int((int)frame->order);
}


bool frame_hash_less (struct hash_elem* a, struct hash_elem* b, void* aux UNUSED)
{
    struct frame* frame_a = hash_entry(a, struct frame, elem);
    struct frame* frame_b = hash_entry(b, struct frame, elem);
    return frame_a->order < frame_b->order;
}