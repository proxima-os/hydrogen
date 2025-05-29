#ifndef HYDROGEN_X86_64_IO_H
#define HYDROGEN_X86_64_IO_H

#ifdef __cplusplus
extern "C" {
#endif

int hydrogen_x86_64_enable_io_access(void);

void hydrogen_x86_64_disable_io_access(void);

#ifdef __cplusplus
};
#endif

#endif /* HYDROGEN_X86_64_IO_H */
