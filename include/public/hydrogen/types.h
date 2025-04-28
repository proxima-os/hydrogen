#ifndef HYDROGEN_TYPES_H
#define HYDROGEN_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A reference to a kernel object.
 *
 * Besides indicating which object to operate on, a handle also specifies its "rights": what operations are allowed on
 * the object.
 *
 * Handles are local to namespaces. Every thread has an implicit namespace handle with create and close rights.
 * To prevent circular references, the only way to get an explicit handle to a namespace is to create one - in other
 * words, namespace handles cannot be transferred across namespace boundaries.
 */
typedef struct __hydrogen_handle *hydrogen_handle_t;

typedef struct {
    int error;
    union {
        hydrogen_handle_t handle;
        unsigned long integer;
        void *pointer;
    };
} hydrogen_ret_t;

#ifdef __cplusplus
};
#endif

#endif /* HYDROGEN_TYPES_H */
