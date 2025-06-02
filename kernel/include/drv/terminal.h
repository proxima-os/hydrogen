#pragma once

#include "fs/vfs.h"
#include "proc/mutex.h"
#include <hydrogen/termios.h>

typedef struct pty {
    fs_device_t base;
    inode_t inode;
    unsigned index;
    bool have_inode_ref;
    bool locked;

    mutex_t files_lock;
    list_t files;
    bool have_master;

    mutex_t rx_lock;
    ringbuf_t rx;
    list_t rx_read_waiting;
    event_source_t rx_writable_event;

    mutex_t tx_lock;
    ringbuf_t tx;
    list_t tx_read_waiting;
    event_source_t tx_readable_event;
    struct __termios settings;
    struct __winsize size;
    unsigned column;

    mutex_t foreground_lock;
    struct pgroup *foreground;
    struct session *controller;
} pty_t;

void pty_controller_terminate(pty_t *pty, struct session *session);
void pty_group_terminate(pty_t *pty, struct pgroup *group);
