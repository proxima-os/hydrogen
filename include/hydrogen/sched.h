#ifndef HYDROGEN_SCHED_H
#define HYDROGEN_SCHED_H

#ifdef __cplusplus
extern "C" {
#define _Noreturn [[noreturn]]
#endif

_Noreturn void hydrogen_exit(void);

#ifdef __cplusplus
};
#endif

#endif // HYDROGEN_SCHED_H
