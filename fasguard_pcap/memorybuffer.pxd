ctypedef void dealloc_callback(void *p, size_t l, void *arg)

cdef class MemoryBuffer:
    # If this instance is based on another buffer object (e.g., a
    # slice of another MemoryBuffer) then self.base is the other base
    # object, otherwise self.base is None.  A reference to the base is
    # kept to prevent the base from being deallocated, which would
    # invalidate self.p.
    cdef MemoryBuffer base
    cdef void *p
    cdef size_t l
    cdef bint readonly
    cdef dealloc_callback *dealloc_cb_p
    cdef void *dealloc_cb_arg
    cdef bint _valid
    cdef invalidate(MemoryBuffer self)
    cdef _ensure_valid(MemoryBuffer self)
    cpdef startswith(MemoryBuffer self, prefix,
                     ssize_t start=?, ssize_t end=?)

# Call this instead of constructing a MemoryBuffer directly.  The
# __cinit__ and __init__ methods can only take Python objects, so the
# real constructor is here.  See:
# https://mail.python.org/pipermail/cython-devel/2012-June/002734.html
cdef MemoryBuffer MemoryBuffer_init(void *p,
                                    size_t l,
                                    bint readonly=?,
                                    dealloc_callback *dealloc_cb_p=?,
                                    void *dealloc_cb_arg=?)
