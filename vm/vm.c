/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include <hash.h>
#include "vm/uninit.h"
#include "vm/file.h"
#include "vm/anon.h"


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
 * `vm_alloc_page`.
 * DO NOT MODIFY THIS FUNCTION. */
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
		 struct page *page=malloc(sizeof(struct page));
		 if(page==NULL) goto err;
		page->writable=writable;
		switch(VM_TYPE(type)){
			case VM_ANON:
				uninit_new(page, upage, init, type, aux, &anon_initializer);
				break;
			case VM_FILE:
				uninit_new(page, upage,init, type, aux, &file_map_initializer);
				break;
			default:
				break;

		}

		/* TODO: Insert the page into the spt. */
		return spt_insert_page(spt, page);
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page *page = NULL;
	struct hash_elem *hash_elem=NULL;
	/* TODO: Fill this function. */
	page=malloc(sizeof(struct page));
	page->va=va;
	hash_elem=hash_find(&spt->hash_table, &page->hash_elem);
	
	free(page);

	if(hash_elem==NULL) return NULL;
	else return hash_entry(hash_elem, struct page, hash_elem);
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	int succ = false;
	/* TODO: Fill this function. */
	struct hash_elem *hash_elem=hash_insert(&spt->hash_table, &page->hash_elem);
	if(hash_elem==NULL) succ=true;
	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	if(hash_delete(&spt->hash_table, &page->hash_elem)){
	vm_dealloc_page (page);
	return true;}
	return false;
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
	frame=malloc(sizeof(struct frame));
	ASSERT (frame != NULL);

	frame->kva=palloc_get_page(PAL_USER);
	if(frame->kva==NULL){PANIC("todo");}
	frame->page=NULL;
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
	void *bottom=pg_round_down(addr);
	if(vm_alloc_page(VM_MARKER_0|VM_ANON, bottom, true)){
		vm_claim_page(bottom);
		bottom+=PGSIZE;
	}
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
	uintptr_t rsp;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	page=spt_find_page(spt, addr);
	if(write&&!not_present) exit(-1);
	rsp=thread_current()->rsp;
	if(user){
		if(!is_user_vaddr(addr)) return false;
		else{
			thread_current()->rsp=f->rsp;
		}
	}

	if(page==NULL){
		vm_stack_growth(addr);
		return true;
	}	
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
	page=spt_find_page(&thread_current()->spt, va);
	if(page==NULL) return false;
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

unsigned page_hash(struct hash_elem *hash_e, void *aux UNUSED){
	struct page *page=hash_entry(hash_e, struct page,hash_elem );
	return hash_bytes(&page->va, sizeof page->va);
}
bool page_compare(const struct hash_elem *e1, const struct hash_elem *e2, void *aux UNUSED){
	bool big;
	const struct page *p1=hash_entry(e1, struct page, hash_elem);
	const struct page *p2=hash_entry(e2, struct page, hash_elem);
	if(p1->va<p2->va) return true;
	else false;
}

void vm_destroy(struct hash_elem *hash_e, void *aux){
	struct page *page=hash_entry(hash_e, struct page, hash_elem);
	destroy(page);
	free(page);
}
/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	hash_init(&spt->hash_table,page_hash,page_compare,NULL );
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
			/*firstly I have copied with memcpy but is this right?*/
/*			struct hash_iterator i;
			struct page *original, *copied;
			hash_first(&i, &src->hash_table);
			while(hash_next(&i)){
				original=hash_entry(hash_cur(&i), struct page, hash_elem);
				copied=spt_find_page(dst, original->va);

				if(original->frame!=NULL){
					memcpy(copied->frame->kva, original->frame->kva, PGSIZE);
				}
			}
*/
	ASSERT(dst == &thread_current()->spt);
	struct hash_iterator i;
	bool succ;
	struct lazy_aux *lazy_aux;
	hash_first (&i, &src->hash_table);
	while (hash_next (&i)) {
		struct page *src_page = hash_entry(hash_cur(&i), struct page, hash_elem);
		switch (src_page->operations->type)
		{
			case VM_UNINIT:
				//struct lazy_aux *lazy_aux;
				lazy_aux = malloc(sizeof(struct lazy_aux));
				memcpy(lazy_aux, src_page->uninit.aux, sizeof(struct lazy_aux));
				succ = vm_alloc_page_with_initializer(page_get_type(src_page), src_page->va, src_page->writable, src_page->uninit.init,lazy_aux);			
				break;
			default:
				succ = vm_alloc_page(src_page->operations->type, src_page->va, src_page->writable);
				if (succ){
					struct page *dst_page = spt_find_page(&thread_current()->spt, src_page->va);
					if(!vm_claim_page(src_page->va))
					{
						PANIC("todo");
					}
					memcpy(dst_page->frame->kva, src_page->frame->kva, PGSIZE);
				}
				break;
		}
	}
	return succ;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	hash_clear(&spt->hash_table, vm_destroy);
}
