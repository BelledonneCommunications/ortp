#ifndef _ORTP_TESTER_H
#define _ORTP_TESTER_H

#include <bctoolbox/tester.h>

extern test_suite_t fec_test_suite;

void ortp_tester_init(void (*ftester_printf)(int level, const char *fmt, va_list args));
void ortp_tester_uninit(void);
#endif