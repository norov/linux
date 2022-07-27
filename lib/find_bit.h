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

#define FIND_NEXT_BIT(EXPRESSION, nbits, start)					\
({										\
	unsigned long mask, idx, tmp, __nbits = (nbits), __start = (start);	\
										\
	if (unlikely(__start >= __nbits))					\
		goto out;							\
										\
	mask = word_op(BITMAP_FIRST_WORD_MASK(__start));			\
	idx = __start / BITS_PER_LONG;						\
										\
	for (tmp = (EXPRESSION) & mask; !tmp; tmp = (EXPRESSION)) {		\
		if (idx > __nbits / BITS_PER_LONG)				\
			goto out;						\
		idx++;								\
	}									\
										\
	__nbits = min(idx * BITS_PER_LONG + __ffs(word_op(tmp)), __nbits);	\
out:										\
	__nbits;								\
})

#endif /* _LIB_FIND_BIT_H */
