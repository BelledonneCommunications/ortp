/*
 * Copyright (c) 2010-2022 Belledonne Communications SARL.
 *
 * This file is part of oRTP 
 * (see https://gitlab.linphone.org/BC/public/ortp).
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
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