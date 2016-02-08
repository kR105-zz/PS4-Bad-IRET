#include "threadshit.h"

#define printf(format, ...)\
	do {\
		char buffer[512];\
		int size = sprintf(buffer, format, ##__VA_ARGS__);\
		sceNetSend(sock, buffer, size, 0);\
	} while(0)

#define CORE 6

#define FALSE_SS_BASE  0x10000UL
#define MAP_SIZE    0x10000
#define MAP_ANON	0x0002
#define I386_SET_LDT	1
#define	LDT_AUTO_ALLOC	0xffffffff
#define	SDT_MEMRWA	19
#define	AMD64_GET_GSBASE 130
#define AMD64_SET_GSBASE 131

struct idt_ptr_struct
{
	uint16_t limit;             // Size of IDT table
	uint64_t base;              // Base address of IDT table
} __attribute__((packed));

struct idt_entry_struct
{
	uint16_t target_offset_low;
	uint16_t target_selector;
	uint8_t  ist_reserved_bits;
	uint8_t  access_bits;
	uint16_t target_offset_mid;
	uint32_t target_offset_high;
	uint32_t reserved;
} __attribute__((packed));

typedef struct idt_entry_struct idt_entry_t;
typedef struct idt_ptr_struct idt_ptr_t;

struct	user_segment_descriptor {
	uint64_t sd_lolimit:16;	/* segment extent (lsb) */
	uint64_t sd_lobase:24;		/* segment base address (lsb) */
	uint64_t sd_type:5;		/* segment type */
	uint64_t sd_dpl:2;		/* segment descriptor priority level */
	uint64_t sd_p:1;		/* segment descriptor present */
	uint64_t sd_hilimit:4;		/* segment extent (msb) */
	uint64_t sd_xx:1;		/* unused */
	uint64_t sd_long:1;		/* long mode (cs only) */
	uint64_t sd_def32:1;		/* default 32 vs 16 bit size */
	uint64_t sd_gran:1;		/* limit granularity (byte/page units)*/
	uint64_t sd_hibase:8;		/* segment base address  (msb) */
} __attribute__((packed));

struct i386_ldt_args {
	unsigned int start;
	struct user_segment_descriptor *descs __attribute__((packed));
	unsigned int num;
};

#define	KKST_MAXLEN	1024
#define CTL_KERN         1
#define KERN_OSTYPE      1
#define KERN_PROC        14
#define KERN_PROC_KSTACK 15
#define	IDT_PF		14	/* #PF: Page Fault */

typedef unsigned int lwpid_t;

struct kinfo_kstack {
	lwpid_t	 kkst_tid;			/* ID of thread. */
	int	 kkst_state;			/* Validity of stack. */
	char	 kkst_trace[KKST_MAXLEN];	/* String representing stack. */
	int	 _kkst_ispare[16];		/* Space for more stuff. */
};

struct sendto_args {
	int	s;
	void *	buf;
	size_t	len;
	int	flags;
	void *	to;
	int	tolen;
};

#define EINTR 4

struct auditinfo_addr {
	/*
	8	ai_auid;
	16	ai_mask;
	28	ai_termid;
	8	ai_asid;
	8	ai_flags;
	*/
	char useless[68];
};

struct ucred {
	void *useless1;
	uint64_t cr_uid;
	uint64_t cr_ruid;
	void *useless2;
	void *useless3;
	uint64_t cr_rgid;
	void *useless4;
	void *useless5;
	void *useless6;
	void *cr_prison;
	void *useless7;
	void *useless8;
	void *useless9;
	void *useless10;
	struct auditinfo_addr useless11;
	uint64_t *cr_groups;
};

struct proc {
	char useless[40];
	struct ucred *p_ucred;
};

struct thread {
	void *useless;
	struct proc *td_proc;
};

typedef int64_t register_t;
#define	PAD_(t)	(sizeof(register_t) <= sizeof(t) ? \
		0 : sizeof(register_t) - sizeof(t))


#define	PADL_(t)	0
#define	PADR_(t)	PAD_(t)

struct reboot_args {
	char opt_l_[PADL_(int)]; int opt; char opt_r_[PADR_(int)];
};

static unsigned short LDT3(int idx)
{
	return (idx << 3) | 7;
}

static int i386_set_ldt2(int start, struct user_segment_descriptor *descs, int num)
{
	struct i386_ldt_args p;

	p.start = start;
	p.descs = descs;
	p.num   = num;

	return sysarch(I386_SET_LDT, &p);
}

int stick_this_thread_to_core(int core_id) {
	cpuset_t cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(core_id, &cpuset);

	void *current_thread = pthread_self();
	return pthread_setaffinity_np(current_thread, sizeof(cpuset_t), &cpuset);
}


int amd64_set_gsbase(void *base) {
	return sysarch(AMD64_SET_GSBASE, &base);
}

int amd64_get_gsbase(void **addr) {
	return (sysarch(AMD64_GET_GSBASE, addr));
}

void prefault(void *address, size_t size) {
	uint64_t i;
	for(i = 0; i < size; i++) {
		volatile uint8_t c;
		(void)c;
		
		c = ((char *)address)[i];
	}
}

