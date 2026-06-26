/* Bypass all KLEE symbolic input — for measuring concrete-input floor. */
#ifndef CONCRETE_SHIM_H
#define CONCRETE_SHIM_H
#include <string.h>
#define klee_make_symbolic(p, sz, name) memset((void*)(p), 0, (sz))
#define klee_assume(x) ((void)(x))
#define klee_int(name)  1
#define klee_int_t(name, t) 1
#endif
