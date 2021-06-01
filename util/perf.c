/*
 *  This file is taken from the optimized implementation of the Picnic
 *  signature scheme.
 *  The code is provided under the MIT license:
 *
 * Copyright (c) 2019-2020 Sebastian Ramacher, AIT
 * Copyright (c) 2016-2020 Graz University of Technology
 * Copyright (c) 2017 Angela Promitzer

 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the ""Software""), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "perf.h"

#include <limits.h>
#include <string.h>
#include <time.h>

#if defined(__linux__)
#include <linux/perf_event.h>
#include <linux/version.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

static void perf_close(timing_context_t* ctx) {
  if (ctx->data.fd != -1) {
    close(ctx->data.fd);
    ctx->data.fd = -1;
  }
}

static uint64_t perf_read(timing_context_t* ctx) {
  uint64_t tmp_time;
  if (read(ctx->data.fd, &tmp_time, sizeof(tmp_time)) != sizeof(tmp_time)) {
    return UINT64_MAX;
  }

  return tmp_time;
}

static int perf_event_open(struct perf_event_attr* event, pid_t pid, int cpu,
                           int gfd, unsigned long flags) {
  const long fd = syscall(__NR_perf_event_open, event, pid, cpu, gfd, flags);
  if (fd > INT_MAX) {
    /* too large to handle, but should never happen */
    return -1;
  }

  return fd;
}

static bool perf_init(timing_context_t* ctx) {
  struct perf_event_attr pea;
  memset(&pea, 0, sizeof(pea));

  pea.size = sizeof(pea);
  pea.type = PERF_TYPE_HARDWARE;
  pea.config = PERF_COUNT_HW_CPU_CYCLES;
  pea.disabled = 0;
  pea.exclude_kernel = 1;
  pea.exclude_hv = 1;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
  pea.exclude_callchain_kernel = 1;
  pea.exclude_callchain_user = 1;
#endif

  const int fd = perf_event_open(&pea, 0, -1, -1, 0);
  if (fd == -1) {
    return false;
  }

  ctx->read = perf_read;
  ctx->close = perf_close;
  ctx->data.fd = fd;
  return true;
}
#endif

static void clock_close(timing_context_t* ctx) { (void)ctx; }

static uint64_t clock_read(timing_context_t* ctx) {
  (void)ctx;
  return clock() * (1000000 / CLOCKS_PER_SEC);
}

static bool clock_init(timing_context_t* ctx) {
  ctx->read = clock_read;
  ctx->close = clock_close;
  return true;
}

bool timing_init(timing_context_t* ctx) {
#if defined(__linux__)
  if (perf_init(ctx)) {
    return true;
  }
#endif
  return clock_init(ctx);
}
