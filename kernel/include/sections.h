#pragma once

// .requests* is sorted by name. .requests0 has the start marker, .requests2 has the end marker
#define LIMINE_REQ __attribute__((used, section(".requests1")))

#define INIT_TEXT __attribute__((section(".init.text")))
#define INIT_DATA __attribute__((section(".init.data")))
