from cpython.buffer cimport PyBuffer_FillInfo

cdef class MemoryBuffer:

    def __cinit__(self, *args, **kwargs):
        self.valid = True

    def __dealloc__(self):
        if self.dealloc_cb_p != NULL:
            self.dealloc_cb_p(self.p, self.l, self.dealloc_cb_arg)

    cdef invalidate(MemoryBuffer self):
        self.valid = False

    cdef _ensure_valid(MemoryBuffer self):
        if not self.valid:
            raise ValueError('MemoryBuffer object is no longer valid')

    def __getbuffer__(self, Py_buffer *view, int flags):
        self._ensure_valid()
        # must use PyBuffer_FillInfo() instead of populating the
        # struct directly because PyBuffer_FillInfo() sets the
        # undocumented 'obj' member of Py_buffer to the 2nd arg (self)
        # and increments the ref count to ensure that this object
        # stays alive until the buffer view has been released.  (I
        # would have expected PyObject_GetBuffer() to do both of
        # these, but it doesn't.)
        PyBuffer_FillInfo(view, self, self.p, self.l, self.readonly, flags)

    def __releasebuffer__(self, Py_buffer *view):
        pass

cdef MemoryBuffer MemoryBuffer_init(void *p,
                                    size_t l,
                                    bint readonly=True,
                                    dealloc_callback *dealloc_cb_p=NULL,
                                    void *dealloc_cb_arg=NULL):
    cdef MemoryBuffer ret = MemoryBuffer()
    ret.p = p
    ret.l = l
    ret.readonly = readonly
    ret.dealloc_cb_p = dealloc_cb_p
    ret.dealloc_cb_arg = dealloc_cb_arg
    return ret
