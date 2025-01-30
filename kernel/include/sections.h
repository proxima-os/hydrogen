#pragma once

// .requests* is sorted by name. .requests0 has the start marker, .requests2 has the end marker
#define LIMINE_REQ __attribute__((used, section(".requests1")))
