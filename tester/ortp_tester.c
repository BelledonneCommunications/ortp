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

#include <bctoolbox/defs.h>

#include "ortp_tester_utils.h"

static FILE *log_file = NULL;

static void log_handler(int lev, const char *fmt, va_list args) {
#ifdef _WIN32
	vfprintf(lev == BCTBX_LOG_ERROR ? stderr : stdout, fmt, args);
	fprintf(lev == BCTBX_LOG_ERROR ? stderr : stdout, "\n");
#else
	va_list cap;
	va_copy(cap, args);
	/* Otherwise, we must use stdio to avoid log formatting (for autocompletion etc.) */
	vfprintf(lev == BCTBX_LOG_ERROR ? stderr : stdout, fmt, cap);
	fprintf(lev == BCTBX_LOG_ERROR ? stderr : stdout, "\n");
	va_end(cap);
#endif

	if (log_file) {
		bctbx_logv_out(BCTBX_LOG_DOMAIN, lev, fmt, args);
	}
}

int ortp_tester_set_log_file(const char *filename) {
	if (log_file) {
		fclose(log_file);
	}

	log_file = fopen(filename, "w");
	if (!log_file) {
		bctbx_error("Cannot open file [%s] for writing logs because [%s]", filename, strerror(errno));
		return -1;
	}

	bctbx_message("Redirecting traces to file [%s]", filename);
#if defined(__clang__) || ((__GNUC__ == 4 && __GNUC_MINOR__ >= 6) || __GNUC__ > 4)
#pragma GCC diagnostic push
#endif
#if defined(__clang__) || defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
#ifdef _MSC_VER
#pragma deprecated(message_state_changed_cb)
#endif
	bctbx_set_log_file(log_file);
#if defined(__clang__) || ((__GNUC__ == 4 && __GNUC_MINOR__ >= 6) || __GNUC__ > 4)
#pragma GCC diagnostic pop
#endif

	return 0;
}

int silent_arg_func(BCTBX_UNUSED(const char *arg)) {
	bctbx_set_log_level("ortp", BCTBX_LOG_ERROR);
	bctbx_set_log_level(BCTBX_LOG_DOMAIN, BCTBX_LOG_ERROR);
	return 0;
}

int verbose_arg_func(BCTBX_UNUSED(const char *arg)) {
	bctbx_set_log_level("ortp", BCTBX_LOG_DEBUG);
	bctbx_set_log_level(BCTBX_LOG_DOMAIN, BCTBX_LOG_DEBUG);
	return 0;
}

int logfile_arg_func(const char *arg) {
	if (ortp_tester_set_log_file(arg) < 0) return -2;
	return 0;
}

void ortp_tester_init(void (*ftester_printf)(int level, const char *fmt, va_list args)) {
	bc_tester_set_silent_func(silent_arg_func);
	bc_tester_set_verbose_func(verbose_arg_func);
	bc_tester_set_logfile_func(logfile_arg_func);
	if (ftester_printf == NULL) ftester_printf = log_handler;
	bc_tester_init(ftester_printf, BCTBX_LOG_MESSAGE, BCTBX_LOG_ERROR, "raw");

	bc_tester_add_suite(&extension_header_test_suite);
	bc_tester_add_suite(&fec_test_suite);
	bc_tester_add_suite(&rtp_test_suite);
	bc_tester_add_suite(&bundle_test_suite);
}

void ortp_tester_uninit(void) {
	bc_tester_uninit();
}

#if defined(_WIN32) && !defined(MS2_WINDOWS_DESKTOP)
#define BUILD_ENTRY_POINT 0
#else
#define BUILD_ENTRY_POINT 1
#endif

#if BUILD_ENTRY_POINT
int main(int argc, char *argv[]) {
	int i, ret;

	silent_arg_func(NULL);
	ortp_tester_init(NULL);

#ifdef HAVE_CONFIG_H
	// If the tester is not installed we configure it, so it can be launched without installing
	if (!ortp_tester_is_executable_installed(argv[0], "raw/h265-iframe")) {
		bc_tester_set_resource_dir_prefix(ORTP_LOCAL_RESOURCE_LOCATION);
		printf("Resource dir set to %s\n", ORTP_LOCAL_RESOURCE_LOCATION);
	}
#endif

	for (i = 1; i < argc; ++i) {
		ret = bc_tester_parse_args(argc, argv, i);
		if (ret > 0) {
			i += ret - 1;
			continue;
		} else if (ret < 0) {
			bc_tester_helper(argv[0], "");
		}
		return ret;
	}

	bctbx_set_log_level(NULL, BCTBX_LOG_DEBUG);

	ret = bc_tester_start(argv[0]);
	ortp_tester_uninit();
	return ret;
}
#endif
