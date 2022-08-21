/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _LIB_FIND_BIT_H
#define _LIB_FIND_BIT_H

#ifndef word_op
#define word_op
#endif

#define FIND_FIRST_BIT(EXPRESSION, size)					\
({										\
	unsigned long idx, val, sz = (size);					\
										\
	for (idx = 0; idx * BITS_PER_LONG < sz; idx++) {			\
		val = (EXPRESSION);						\
		if (val) {							\
			sz = min(idx * BITS_PER_LONG + __ffs(word_op(val)), sz);\
			break;							\
		}								\
	}									\
										\
	sz;									\
})

#endif /* _LIB_FIND_BIT_H */
