ctypedef void dealloc_callback(void *p, size_t l, void *arg)

cdef class MemoryBuffer:
    cdef void *p
    cdef size_t l
    cdef bint readonly
    cdef dealloc_callback *dealloc_cb_p
    cdef void *dealloc_cb_arg
    cdef readonly bint valid
    cdef invalidate(MemoryBuffer self)
    cdef _ensure_valid(MemoryBuffer self)

# Call this instead of constructing a MemoryBuffer directly.  The
# __cinit__ and __init__ methods can only take Python objects, so the
# real constructor is here.  See:
# https://mail.python.org/pipermail/cython-devel/2012-June/002734.html
cdef MemoryBuffer MemoryBuffer_init(void *p,
                                    size_t l,
                                    bint readonly=?,
                                    dealloc_callback *dealloc_cb_p=?,
                                    void *dealloc_cb_arg=?)
