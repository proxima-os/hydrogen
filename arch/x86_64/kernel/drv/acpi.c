#include "uacpi/kernel_api.h"
#include "uacpi/status.h"
#include "uacpi/utilities.h"

uacpi_status uacpi_kernel_initialize(uacpi_init_level current_init_lvl) {
    switch (current_init_lvl) {
    case UACPI_INIT_LEVEL_NAMESPACE_LOADED: return uacpi_set_interrupt_model(UACPI_INTERRUPT_MODEL_IOAPIC);
    default: return UACPI_STATUS_OK;
    }
}

void uacpi_kernel_deinitialize(void) {
}
