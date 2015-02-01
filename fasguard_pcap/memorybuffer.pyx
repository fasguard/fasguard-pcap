from cpython.buffer cimport PyBUF_SIMPLE, PyBuffer_FillInfo, \
    PyBuffer_Release, PyObject_CheckBuffer, PyObject_GetBuffer
from cpython.number cimport PyIndex_Check, PyNumber_AsSsize_t
from cpython.slice cimport PySlice_Check, PySlice_GetIndicesEx
from libc.string cimport memcmp, memcpy, memmove

cdef extern from "Python.h":
    enum: PY_SSIZE_T_MAX

cdef class MemoryBuffer:

    property valid:
        def __get__(self):
            if self.base is not None:
                return self.base.valid
            return self._valid

    def __cinit__(self, MemoryBuffer base=None, *args, **kwargs):
        self.base = base
        self._valid = True

    def __dealloc__(self):
        if self.dealloc_cb_p != NULL:
            self.dealloc_cb_p(self.p, self.l, self.dealloc_cb_arg)

    cdef invalidate(MemoryBuffer self):
        if self.base is not None:
            self.base.invalidate()
        self._valid = False

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

    def __repr__(self):
        self._ensure_valid()
        return 'MemoryBuffer(' + repr(memoryview(self).tobytes()) + ')'

    def __len__(self):
        self._ensure_valid()
        return self.l

    def __getitem__(self, key):
        self._ensure_valid()
        cdef Py_ssize_t i, j, step, slicelength
        cdef MemoryBuffer slice
        if PyIndex_Check(key):
            i = PyNumber_AsSsize_t(key, OverflowError)
            if i < 0:
                i += self.l
            if (i < 0) or (i >= self.l):
                raise IndexError('index out of bounds')
            return <bytes>(<unsigned char *>self.p)[i:i+1]
        elif PySlice_Check(key):
            PySlice_GetIndicesEx(key, self.l, &i, &j, &step, &slicelength)
            if step != 1:
                raise NotImplementedError('MemoryBuffer slice step must be 1')
            slice = MemoryBuffer(self)
            slice.p = (<unsigned char *>self.p) + i
            slice.l = slicelength
            slice.readonly = self.readonly
            return slice
        else:
            raise TypeError('unable to index memory using object of type ' \
                            + key.__class__.__name__)

    def __setitem__(self, key, value):
        self._ensure_valid()
        if self.readonly:
            raise TypeError('cannot modify read-only memory')
        if value is None:
            raise TypeError('cannot delete memory')
        if not PyObject_CheckBuffer(value):
            raise TypeError('value does not follow the buffer protocol')
        cdef Py_ssize_t i, j, step, slicelen
        if PyIndex_Check(key):
            i = PyNumber_AsSsize_t(key, OverflowError)
            if i < 0:
                i += self.l
            if (i < 0) or (i >= self.l):
                raise IndexError('index out of bounds')
            slicelen = 1
        elif PySlice_Check(key):
            PySlice_GetIndicesEx(key, self.l, &i, &j, &step, &slicelen)
            if step != 1:
                raise NotImplementedError('MemoryBuffer slice step must be 1')
        else:
            raise TypeError('unable to index memory using object of type ' \
                            + key.__class__.__name__)
        cdef Py_buffer srcview
        # must be char * to do bytewise pointer arithmetic
        cdef char *dst
        cdef char *src
        PyObject_GetBuffer(value, &srcview, PyBUF_SIMPLE)
        try:
            if slicelen != srcview.len:
                raise ValueError('cannot modify size of MemoryBuffer object')
            dst = (<char *>self.p) + i
            src = <char *>srcview.buf
            if ((dst + slicelen) < src) or ((src + slicelen) < dst):
                # no overlap
                memcpy(dst, src, slicelen)
            else:
                memmove(dst, src, slicelen)
        finally:
            PyBuffer_Release(&srcview)

    cpdef startswith(MemoryBuffer self, prefix,
                     ssize_t start=0, ssize_t end=PY_SSIZE_T_MAX):
        self._ensure_valid()
        if not PyObject_CheckBuffer(prefix):
            raise TypeError('prefix does not follow the buffer protocol')

        if start < 0:
            start += self.l
        if start < 0:
            start = 0
        if start > self.l:
            start = self.l
        if end < 0:
            end += self.l
        if end < 0:
            end = 0
        if end > self.l:
            end = self.l
        if end < start:
            end = start
        cdef ssize_t l = end - start

        cdef Py_buffer view
        PyObject_GetBuffer(prefix, &view, PyBUF_SIMPLE)
        try:
            if view.len == 0:
                # trivial: all strings begin with an empty string
                return True
            if view.len > l:
                # trivial: prefix is longer than this string
                return False
            return not memcmp(self.p + start, view.buf, view.len)
        finally:
            PyBuffer_Release(&view)

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
