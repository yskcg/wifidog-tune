#ifndef __math_compat_h
#define __math_compat_h
#define __builtin_isnan(x) x
#define __builtin_isinf(x) x

#undef isnan
#define isnan(x) __builtin_isnan(x)
#undef isinf
#define isinf(x) __builtin_isinf(x)

#endif
