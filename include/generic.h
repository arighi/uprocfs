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

/* Are two types/vars the same type (ignoring qualifiers)? */
#ifndef __same_type
#define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#endif

/* Force a compile-time error if condition is true */
#define BUILD_BUG_ON_ZERO(e) (sizeof(struct { int:-!!(e); }))

/* &a[0] degrades to a pointer: a different type from an array */
#define __must_be_array(a) BUILD_BUG_ON_ZERO(__same_type((a), &(a)[0]))

/*
 * Return the size of an array in elements (+ check that it is actually a
 * static array and not a pointer).
 */
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))

#endif /* _GENERIC_H */
