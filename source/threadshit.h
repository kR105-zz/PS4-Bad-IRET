typedef	unsigned long		__uint64_t;
typedef	__uint64_t	__size_t;

#define howmany(x,y)	(((x)+((y)-1))/(y))

#define NBBY	8
#define	CPU_SETSIZE	8
#define	_NCPUBITS	(sizeof(long) * NBBY)	/* bits per mask */
#define	_NCPUWORDS	howmany(CPU_SETSIZE, _NCPUBITS)

#define	__cpuset_mask(n)	((long)1 << ((n) % _NCPUBITS))

#define	CPU_SET(n, p)	((p)->__bits[(n)/_NCPUBITS] |= __cpuset_mask(n))
#define	CPU_ZERO(p) do {				\
	__size_t __i;					\
	for (__i = 0; __i < _NCPUWORDS; __i++)		\
		(p)->__bits[__i] = 0;			\
} while (0)

typedef	struct _cpuset {
	long	__bits[howmany(CPU_SETSIZE, _NCPUBITS)];
} cpuset_t;

typedef struct	pthread			*pthread_t;

int stick_this_thread_to_core(int core_id);
