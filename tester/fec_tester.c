#include "ortp_tester.h"
#include <ortp/ortp.h>

static void first_basic_test(void) {
	int *p = NULL;
	BC_ASSERT_PTR_NULL(p);
}

static test_t tests[] = {
	TEST_NO_TAG("first", first_basic_test)
};

test_suite_t fec_test_suite = {
	"FEC",							  // Name of test suite
	NULL,							  // Before all callback
	NULL,							  // After all callback
	NULL,							  // Before each callback
	NULL,							  // After each callback
	sizeof(tests) / sizeof(tests[0]), // Size of test table
	tests							  // Table of test suite
};