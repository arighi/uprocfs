#ifndef _GENERIC_H
#define _GENERIC_H

#ifndef container_of
/**
 * container_of - cast a member of a structure out to the containing structure
 *
 * @ptr:        the pointer to the member.
 * @type:       the type of the container struct this is embedded in.
 * @member:     the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({                      \
	const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
	(type *)( (char *)__mptr - offsetof(type,member) );})
#endif

#define likely(x)	__builtin_expect(!!(x), 1)
#define unlikely(x)	__builtin_expect(!!(x), 0)

#define max(x,y)	((y)<(x)?(x):(y))
#define min(x,y)	((y)>(x)?(x):(y))

/*
 * Indirect stringification. Doing two levels allows the parameter to be a
 * macro itself.  For example, compile with -DFOO=bar, __stringify(FOO)
 * converts to "bar".
 */
#define __stringify_1(x...)	#x
#define __stringify(x...)	__stringify_1(x)

/* Structure aligned to the cahe line size */
#define __cacheline_aligned __attribute__((__aligned__(CACHELINE_SIZE)))

#endif /* _GENERIC_H */
