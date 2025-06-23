#include "util/time.h"
#include "arch/divide.h"
#include "arch/irq.h"
#include "arch/time.h"
#include "cpu/cpudata.h"
#include "init/task.h"
#include "kernel/compiler.h"
#include "kernel/vdso.h"
#include "limine.h"
#include "proc/mutex.h"
#include "sections.h"
#include "util/spinlock.h"
#include <stdint.h>

static void time_init(void) {
    static LIMINE_REQ struct limine_date_at_boot_request time_req = {.id = LIMINE_DATE_AT_BOOT_REQUEST};

    if (time_req.response) {
        set_current_timestamp((__int128_t)time_req.response->timestamp * NS_PER_SEC);
    }
}

INIT_DEFINE_EARLY(time, time_init, INIT_REFERENCE(arch_time));

__int128_t get_current_timestamp(void) {
    return real_time_from_boot_time(arch_read_time());
}

void set_current_timestamp(__int128_t time) {
    static mutex_t timestamp_update_lock;
    mutex_acq(&timestamp_update_lock, 0, false);

    __uint128_t u = time;

    size_t seq = __atomic_load_n(&vdso_info.boot_timestamp_seq, __ATOMIC_RELAXED);
    __atomic_store_n(&vdso_info.boot_timestamp_seq, seq + 1, __ATOMIC_RELAXED);
    __atomic_thread_fence(__ATOMIC_RELEASE);

    __atomic_store_n(&vdso_info.boot_timestamp_low, u, __ATOMIC_RELAXED);
    __atomic_store_n(&vdso_info.boot_timestamp_high, u >> 64, __ATOMIC_RELAXED);

    __atomic_store_n(&vdso_info.boot_timestamp_seq, seq + 2, __ATOMIC_RELEASE);

    mutex_rel(&timestamp_update_lock);
}

timeconv_t timeconv_create(uint64_t src_freq, uint64_t dst_freq) {
    /*
     * Time conversion is `T1 = (T1 * f1) / f0` (T0 = src value, f0 = src freq, T1 = dst value, f1 = dst freq).
     * However, that formula can overflow pretty quickly if the source frequency is high, making it unusable.
     * A workaround for this is using 128-bit integers for the intermediate value, but 128-bit division is either slow
     * or impossible depending on the platform. 128-bit multiplication is fine, though, and the equation can be
     * rearranged to not include 128-bit division:
     * 1. `T1 = (T1 * f1) / f0`
     * 2. `T1 = (T1 * f1 * 2^p) / (f0 * 2^p)`
     * 3. `T1 = (T1 * ((f1 * 2^p) / f0)) / 2^p`
     * Note that `((f1 * 2^p) / f0)` is a constant that can be calculated ahead of time, and the last division
     * is by a power of two and can thus be replaced with a right shift. This function calculates both `p` and
     * that constant.
     */

    // Find the highest value of `p` that doesn't make the multiplier overflow (`((f1 * 2^p) / f0) < 2^64`)

    // the highest value of `p` where the intermediate uint128_t can still be calculated
    unsigned max_p_intermediate = __builtin_clzl(dst_freq) + (128 - (sizeof(long) * 8));

    unsigned p;
    uint64_t multiplier;

    for (p = 0; p <= max_p_intermediate; p++) {
        __uint128_t cur_mult = (__uint128_t)dst_freq << p;
        udiv128(&cur_mult, src_freq);
        if (cur_mult > UINT64_MAX) break;
        multiplier = cur_mult;
    }

    p -= 1;

    return (timeconv_t){
        .multiplier = multiplier,
        .shift = p,
    };
}

static timer_event_t *meld(timer_event_t *a, timer_event_t *b) {
    if (!a) return b;
    if (!b) return a;

    if (b->deadline < a->deadline) {
        timer_event_t *tmp = a;
        a = b;
        b = tmp;
    }

    b->parent = a;
    b->prev = NULL;
    b->next = a->children;
    if (a->children) a->children->prev = b;
    a->children = b;
    return a;
}

static void remove_event(cpu_t *cpu, timer_event_t *event) {
    timer_event_t *pairs = NULL;

    while (event->children) {
        timer_event_t *a = event->children;
        timer_event_t *b = a->next;
        event->children = b ? b->next : NULL;

        timer_event_t *melded = meld(a, b);
        melded->parent = pairs;
        pairs = melded;
    }

    timer_event_t *replacement = NULL;

    while (pairs) {
        timer_event_t *pair = pairs;
        pairs = pair->parent;
        replacement = meld(pair, replacement);
    }

    if (replacement != NULL) {
        if (event->parent != NULL) {
            replacement->parent = event->parent;
            replacement->prev = event->prev;
            replacement->next = event->next;

            if (event->prev) event->prev->next = replacement;
            else event->parent->children = replacement;

            if (event->next) event->next->prev = replacement;
        } else {
            replacement->parent = NULL;
            cpu->events = replacement;
        }
    } else if (event->parent != NULL) {
        if (event->prev) event->prev->next = event->next;
        else event->parent->children = event->next;

        if (event->next) event->next->prev = event->prev;
    } else {
        cpu->events = NULL;
    }
}

void time_handle_irq(void) {
    cpu_t *cpu = get_current_cpu();
    spin_acq_noirq(&cpu->events_lock);

    timer_event_t *event;

    timer_event_t *head = NULL;
    timer_event_t *tail = NULL;

    for (;;) {
        event = cpu->events;
        if (!event || arch_read_time() < event->deadline) break;

        remove_event(cpu, event);

        event->next = NULL;
        if (head) tail->next = event;
        else head = event;
        tail = event;

        __atomic_store_n(&event->cpu, NULL, __ATOMIC_RELEASE);
        __atomic_store_n(&event->running, true, __ATOMIC_RELEASE);
    }

    if (event != NULL) {
        arch_queue_timer_irq(event->deadline);
    }

    spin_rel_noirq(&cpu->events_lock);

    for (;;) {
        timer_event_t *event = head;
        if (!event) break;
        head = event->next;
        void (*func)(timer_event_t *) = event->func;
        __atomic_store_n(&event->running, false, __ATOMIC_RELEASE);
        func(event);
    }
}

void timer_queue_event(timer_event_t *event) {
    ASSERT(__atomic_load_n(&event->cpu, __ATOMIC_ACQUIRE) == NULL);
    ASSERT(event->deadline != 0);

    irq_state_t state = save_disable_irq();
    cpu_t *cpu = get_current_cpu();
    spin_acq_noirq(&cpu->events_lock);

    event->children = NULL;
    event->prev = NULL;
    event->next = NULL;
    cpu->events = meld(cpu->events, event);
    cpu->events->parent = NULL;

    __atomic_store_n(&event->cpu, cpu, __ATOMIC_RELEASE);

    if (event == cpu->events) {
        arch_queue_timer_irq(event->deadline);
    }

    spin_rel_noirq(&cpu->events_lock);
    restore_irq(state);
}

static void ensure_not_running(timer_event_t *event) {
    for (;;) {
        if (!__atomic_load_n(&event->running, __ATOMIC_ACQUIRE)) return;
    }
}

void timer_cancel_event(timer_event_t *event) {
    cpu_t *cpu = __atomic_load_n(&event->cpu, __ATOMIC_ACQUIRE);

    if (cpu == NULL) {
        ensure_not_running(event);
        return;
    }

    irq_state_t state = spin_acq(&cpu->events_lock);

    for (;;) {
        cpu_t *ncpu = __atomic_load_n(&event->cpu, __ATOMIC_ACQUIRE);
        if (ncpu == cpu) break;

        spin_rel_noirq(&cpu->events_lock);
        cpu = ncpu;

        if (cpu == NULL) {
            ensure_not_running(event);
            return;
        }

        spin_acq_noirq(&cpu->events_lock);
    }

    remove_event(cpu, event);
    __atomic_store_n(&event->cpu, NULL, __ATOMIC_RELEASE);

    spin_rel(&cpu->events_lock, state);
    ensure_not_running(event);
}
