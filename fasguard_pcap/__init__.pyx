# cython: c_string_type=str, c_string_encoding=ascii
#
# pcap.pyx
#
# $Id: pcap.pyx,v 1.20 2005/10/16 23:00:11 dugsong Exp $

"""packet capture library

This module provides a high level interface to packet capture systems.
All packets on the network, even those destined for other hosts, are
accessible through this mechanism.
"""

__author__ = 'Dug Song <dugsong@monkey.org>'
__maintainer__ = 'BBN FASGuard team <fasguard@bbn.com>'
__copyright__ = 'Copyright (c) 2004 Dug Song'
__license__ = 'BSD license'
__url__ = 'https://fasguard.github.io/'
__version__ = '1.1'
__revison__ = '2'

from cpython.buffer cimport PyBUF_SIMPLE, PyBuffer_Release, \
    PyObject_CheckBuffer, PyObject_GetBuffer
from cpython.exc cimport PyErr_WarnEx
from cpython.ref cimport PyObject
from posix.time cimport timeval
from posix.types cimport suseconds_t, time_t
import sys
import calendar
import time

cimport fasguard_pcap.bpf
import fasguard_pcap.bpf

from fasguard_pcap.bpf cimport bpf_insn
from fasguard_pcap.bpf cimport bpf_program

from fasguard_pcap.memorybuffer cimport MemoryBuffer, MemoryBuffer_init

cdef extern from "pcap/pcap.h":
    struct pcap_stat:
        unsigned int ps_recv
        unsigned int ps_drop
        unsigned int ps_ifdrop
    struct pcap_pkthdr:
        timeval ts
        unsigned int caplen
        unsigned int len
    ctypedef struct pcap_t:
        int __xxx
    ctypedef struct pcap_dumper_t:
        int __xxx
    ctypedef enum pcap_direction_t:
        __xxx

ctypedef void (*pcap_handler)(unsigned char *arg, const pcap_pkthdr *hdr,
                              const unsigned char *pkt)

cdef extern from "pcap/pcap.h" nogil:
    pcap_t *pcap_open_live(const char *device, int snaplen, int promisc,
                           int to_ms, char *errbuf)
    pcap_t *pcap_open_dead(int linktype, int snaplen)
    pcap_t *pcap_open_dead_with_tstamp_precision(
        int linktype, int snaplen, unsigned int precision)
    pcap_t *pcap_open_offline(char *fname, char *errbuf)
    pcap_t *pcap_open_offline_with_tstamp_precision(
        const char *fname, unsigned int precision, char *errbuf)
    pcap_t *pcap_create(const char *source, char *errbuf)
    int     pcap_activate(pcap_t *p)
    pcap_dumper_t *pcap_dump_open(pcap_t *p, const char *fname)
    void pcap_dump_close(pcap_dumper_t *p)
    int     pcap_compile(pcap_t *p, bpf_program *fp, const char *str,
                         int optimize, unsigned int netmask)
    int     pcap_setfilter(pcap_t *p, bpf_program *fp)
    void    pcap_freecode(bpf_program *fp)
    int     pcap_setdirection(pcap_t *p, pcap_direction_t d)
    int     pcap_dispatch(pcap_t *p, int cnt, pcap_handler callback,
                          unsigned char *arg)
    const unsigned char *pcap_next(pcap_t *p, pcap_pkthdr *hdr)
    int     pcap_datalink(pcap_t *p)
    int     pcap_snapshot(pcap_t *p)
    int     pcap_stats(pcap_t *p, pcap_stat *ps)
    char   *pcap_geterr(pcap_t *p)
    void    pcap_close(pcap_t *p)
    int     pcap_inject(pcap_t *p, const void *buf, size_t size)
    void    pcap_dump(unsigned char *p, const pcap_pkthdr *h,
                      const unsigned char *sp)
    int     pcap_get_selectable_fd(pcap_t *)
    int     pcap_setnonblock(pcap_t *p, int nonblock, char *errbuf)
    int     pcap_getnonblock(pcap_t *p, char *errbuf)
    char   *pcap_lookupdev(char *errbuf)
    int     pcap_compile_nopcap(int snaplen, int dlt, bpf_program *fp,
                                const char *str, int optimize,
                                unsigned int netmask)
    void    pcap_breakloop(pcap_t *p)
    int     pcap_can_set_rfmon(pcap_t *p)
    void    pcap_free_tstamp_types(int *tstamp_types)
    int     pcap_get_tstamp_precision(pcap_t *p)
    int     pcap_list_tstamp_types(pcap_t *p, int **tstamp_typesp)
    int     pcap_set_buffer_size(pcap_t *p, int buffer_size)
    int     pcap_set_promisc(pcap_t *p, int promisc)
    int     pcap_set_rfmon(pcap_t *p, int rfmon)
    int     pcap_set_snaplen(pcap_t *p, int snaplen)
    int     pcap_set_timeout(pcap_t *p, int to_ms)
    int     pcap_set_tstamp_precision(pcap_t *p, int tstamp_precision)
    int     pcap_set_tstamp_type(pcap_t *p, int tstamp_type)
    const char *pcap_statustostr(int error)
    int     pcap_tstamp_type_name_to_val(const char *name)
    const char *pcap_tstamp_type_val_to_name(int tstamp_type)
    cdef enum:
        PCAP_ERRBUF_SIZE
        PCAP_TSTAMP_PRECISION_MICRO
        PCAP_TSTAMP_PRECISION_NANO
        PCAP_WARNING
        PCAP_WARNING_PROMISC_NOTSUP
        PCAP_WARNING_TSTAMP_TYPE_NOTSUP

cdef extern from "pcap_ex.h" nogil:
    int     pcap_ex_immediate(pcap_t *p)
    char   *pcap_ex_name(char *name)
    void    pcap_ex_setup(pcap_t *p)
    int     pcap_ex_next(pcap_t *p, pcap_pkthdr *hdr,
                         unsigned char **pkt)
    char   *pcap_ex_lookupdev(char *errbuf)

cdef str errstr(str msg=None, int error=0):
    """Return an error message string given pcap.geterr() and error number
    """
    cdef str newmsg = ""
    cdef str sep = ""
    if error != 0:
        newmsg = pcap_statustostr(error)
        sep = ": "
    if msg is not None and len(msg) != 0:
        newmsg += sep + msg
    if len(newmsg) == 0:
        newmsg = None
    return newmsg

class PcapError(Exception):
    pass
class PcapWarning(Warning):
    pass

cdef class pcap_handler_ctx:
    cdef object callback
    cdef object args
    cdef object exc_info
    cdef pcap p
    def __cinit__(self, object callback, object args, pcap p):
        self.callback = callback
        self.args = args
        self.exc_info = None
        self.p = p

cdef void __pcap_handler(unsigned char *arg, const pcap_pkthdr *hdr_c,
                         const unsigned char *pkt) with gil:
    cdef pcap_handler_ctx ctx = <pcap_handler_ctx><PyObject *>arg
    if ctx.exc_info is not None:
        # don't want to risk raising another exception, so we'll wait
        # until pcap_breakloop() does its thing
        return
    cdef pkthdr hdr
    cdef MemoryBuffer pkt_mb
    try:
        hdr = pkthdr(ctx.p.tstamp_precision,
                     hdr_c.ts.tv_sec, hdr_c.ts.tv_usec,
                     hdr_c.caplen, hdr_c.len)
        pkt_mb = MemoryBuffer_init(<void *>pkt, hdr.caplen)
        ctx.callback(hdr, pkt_mb, *ctx.args)
        pkt_mb.invalidate()
    except:
        assert ctx.exc_info is None
        ctx.exc_info = sys.exc_info()
        ctx.p.breakloop()

PCAP_D_INOUT = 0
PCAP_D_IN = 1
PCAP_D_OUT = 2

DLT_NULL =	0
DLT_EN10MB =	1
DLT_EN3MB =	2
DLT_AX25 =	3
DLT_PRONET =	4
DLT_CHAOS =	5
DLT_IEEE802 =	6
DLT_ARCNET =	7
DLT_SLIP =	8
DLT_PPP =	9
DLT_FDDI =	10
# XXX - Linux
DLT_LINUX_SLL =	113
# XXX - OpenBSD
DLT_PFLOG =	117
DLT_PFSYNC =	18
if sys.platform.find('openbsd') != -1:
    DLT_LOOP =		12
    DLT_RAW =		14
else:
    DLT_LOOP =		108
    DLT_RAW =		12

dltoff = { DLT_NULL:4, DLT_EN10MB:14, DLT_IEEE802:22, DLT_ARCNET:6,
          DLT_SLIP:16, DLT_PPP:4, DLT_FDDI:21, DLT_PFLOG:48, DLT_PFSYNC:4,
          DLT_LOOP:4, DLT_RAW:0, DLT_LINUX_SLL:16 }

def compile(char *str, int snaplen=65536, int dlt=DLT_RAW, int optimize=1,
            long netmask=0):
    """Compile a pcap filter expression to a BPF program.
       This is not a class method, because we want to do the same
       from within the pcap class."""
    # avoid pcap_compile_nopcap() because it doesn't provide a way to
    # access the error buffer
    with pcap.open_dead(dlt, snaplen) as p:
        return p.compile(str, optimize, netmask)

cdef class pcap:
    """Handle to a packet capture descriptor.

    Attributes:
        filter
            Current packet capture filter.
        name
            Network interface or dumpfile name.
        type
            Packet source type ('live', 'offline', or 'dead').
    """
    cdef pcap_t *__pcap
    cdef readonly bytes name
    cdef readonly bytes filter
    cdef char __ebuf[PCAP_ERRBUF_SIZE]
    cdef readonly str type
    cdef object __promisc
    cdef object __rfmon
    cdef object __timeout
    cdef object __buffer_size
    cdef str __tstamp_type

    @staticmethod
    def open_dead(int linktype, int snaplen,
                  unsigned int precision=PCAP_TSTAMP_PRECISION_MICRO):
        """Open a handle to a packet capture descriptor.

        Keyword arguments:
        linktype  -- link-layer type
        snaplen   -- maximum number of bytes to capture for each packet
        precision -- time stamp precision for packets
        """
        ret = pcap()
        with nogil:
            ret.__pcap = pcap_open_dead_with_tstamp_precision(
                linktype, snaplen, precision)
        if ret.__pcap == NULL:
            raise PcapError("error in pcap_open_dead()")
        ret.type = 'dead'
        return ret

    @staticmethod
    def open_offline(const char *fname,
                     unsigned int precision=PCAP_TSTAMP_PRECISION_MICRO):
        """Open a handle to a packet capture descriptor.

        Keyword arguments:
        fname     -- name of a dumpfile to open
        precision -- time stamp precision for packets
        """
        ret = pcap()
        with nogil:
            ret.__pcap = pcap_open_offline_with_tstamp_precision(
                fname, precision, ret.__ebuf)
        if ret.__pcap == NULL:
            raise PcapError(ret.__ebuf)
        ret.name = fname
        ret.type = 'offline'
        return ret

    @staticmethod
    def open_live(const char *device, int snaplen=65535,
                  bint promisc=True, int to_ms=500):
        """Open a handle to a packet capture descriptor.

        Keyword arguments:
        device  -- name of a network interface to open, or None to
                   open the first available up interface
        snaplen -- maximum number of bytes to capture for each packet
        promisc -- boolean to specify promiscuous mode sniffing
        to_ms   -- read timeout in milliseconds
        """
        ret = pcap()
        with nogil:
            ret.__pcap = pcap_open_live(device, snaplen, promisc, to_ms,
                                        ret.__ebuf)
        if ret.__pcap == NULL:
            raise PcapError(ret.__ebuf)
        ret.name = device
        ret.type = 'live'
        ret.__promisc = promisc
        ret.__timeout = to_ms
        return ret

    @staticmethod
    def create(const char *source):
        ret = pcap()
        with nogil:
            ret.__pcap = pcap_create(source, ret.__ebuf)
        if ret.__pcap == NULL:
            raise PcapError(ret.__ebuf)
        ret.name = source
        ret.type = 'live'
        return ret

    def __cinit__(self, *args, **kwargs):
        self.__promisc = False
        self.__rfmon = False
        self.__timeout = None
        self.__buffer_size = None
        self.__tstamp_type = None

    property snaplen:
        """Maximum number of bytes to capture for each packet."""
        def __get__(self):
            cdef int ret
            with nogil:
                ret = pcap_snapshot(self.__pcap)
            return ret
        def __set__(self, int snaplen):
            cdef int ret
            with nogil:
                ret = pcap_set_snaplen(self.__pcap, snaplen)
            if ret != 0:
                raise PcapError(errstr(self.geterr(), ret))
        
    property promisc:
        def __get__(self):
            if self.type != 'live':
                raise TypeError('not a live packet capture')
            return self.__promisc
        def __set__(self, bint promisc):
            cdef int ret
            with nogil:
                ret = pcap_set_promisc(self.__pcap, promisc)
            if ret != 0:
                raise PcapError(errstr(self.geterr(), ret))
            self.__promisc = promisc

    property rfmon:
        def __get__(self):
            if self.type != 'live':
                raise TypeError('not a live packet capture')
            return self.__rfmon
        def __set__(self, bint rfmon):
            cdef int ret
            with nogil:
                ret = pcap_set_rfmon(self.__pcap, rfmon)
            if ret != 0:
                raise PcapError(errstr(self.geterr(), ret))
            self.__rfmon = rfmon

    property timeout:
        def __get__(self):
            if self.type != 'live':
                raise TypeError('not a live packet capture')
            return self.__timeout
        def __set__(self, int to_ms):
            cdef int ret
            with nogil:
                ret = pcap_set_timeout(self.__pcap, to_ms)
            if ret != 0:
                raise PcapError(errstr(self.geterr(), ret))
            self.__timeout = to_ms

    property buffer_size:
        def __get__(self):
            if self.type != 'live':
                raise TypeError('not a live packet capture')
            return self.__buffer_size
        def __set__(self, int buffer_size):
            cdef int ret
            with nogil:
                ret = pcap_set_buffer_size(self.__pcap, buffer_size)
            if ret != 0:
                raise PcapError(errstr(self.geterr(), ret))
            self.__buffer_size = buffer_size

    property tstamp_type:
        def __get__(self):
            if self.type != 'live':
                raise TypeError('not a live packet capture')
            return self.__tstamp_type
        def __set__(self, str tstamp_type):
            cdef int ts
            cdef const char *tstamp_type_c = tstamp_type
            with nogil:
                ts = pcap_tstamp_type_name_to_val(tstamp_type_c)
            cdef int ret
            with nogil:
                ret = pcap_set_tstamp_type(self.__pcap, ts)
            if ret == PCAP_WARNING_TSTAMP_TYPE_NOTSUP:
                PyErr_WarnEx(PcapWarning, errstr(self.geterr(), ret), 1)
                return
            elif ret != 0:
                raise PcapError(errstr(self.geterr(), ret))
            self.__tstamp_type = tstamp_type

    property tstamp_precision:
        def __get__(self):
            cdef int ret
            with nogil:
                ret = pcap_get_tstamp_precision(self.__pcap)
            return ret
        def __set__(self, int tstamp_precision):
            cdef int ret
            with nogil:
                ret = pcap_set_tstamp_precision(self.__pcap, tstamp_precision)
            if ret != 0:
                raise PcapError(errstr(self.geterr(), ret))

    property dloff:
        """Datalink offset (length of layer-2 frame header)."""
        def __get__(self):
            return dltoff.get(self.datalink(), 0)

    property fd:
        """File descriptor (or Win32 HANDLE) for capture handle."""
        def __get__(self):
            cdef int ret
            with nogil:
                ret = pcap_get_selectable_fd(self.__pcap)
            return ret
        
    def fileno(self):
        """Return file descriptor (or Win32 HANDLE) for capture handle."""
        return self.fd

    cpdef bint can_set_rfmon(self):
        cdef int ret
        with nogil:
            ret = pcap_can_set_rfmon(self.__pcap)
        if ret != 0 and ret != 1:
            raise PcapError(errstr(self.geterr(), ret))
        return ret

    cpdef activate(self):
        cdef int ret
        with nogil:
            ret = pcap_activate(self.__pcap)
        if ret == PCAP_WARNING_PROMISC_NOTSUP \
           or ret == PCAP_WARNING_TSTAMP_TYPE_NOTSUP \
           or ret == PCAP_WARNING:
            PyErr_WarnEx(PcapWarning, errstr(self.geterr(), ret), 1)
        elif ret != 0:
            raise PcapError(errstr(self.geterr(), ret))
    
    def setfilter(self, const char *value, int optimize=1):
        """Set packet capture filter using a filter expression."""
        cdef bpf_program fcode
        self.filter = value
        self.__compile(&fcode, value, optimize, 0)
        self.__setfilter(&fcode)
        with nogil:
            pcap_freecode(&fcode)

    def setbpfprogram(self, object bpfprogram):
        """Set packet capture filter using a pre-compiled BPF program."""
        cdef object pbp
        cdef bpf_program *bp
        #cdef int i
        if not isinstance(bpfprogram, fasguard_pcap.bpf.program):
            raise TypeError()
        # cast to temporary required.
        pbp = fasguard_pcap.bpf.program.__progbuf__(bpfprogram)
        bp = fasguard_pcap.bpf.progbuf.__bpf_program__(pbp)
        self.__setfilter(bp)

    cdef void __setfilter(pcap self, bpf_program *fp):
        cdef int ret
        with nogil:
            ret = pcap_setfilter(self.__pcap, fp)
        if ret < 0:
            raise PcapError(errstr(self.geterr(), ret))

    def compile(self, const char *value, bint optimize=True,
                unsigned int netmask=0):
        """Compile a filter expression to a BPF program for this pcap.
           Return the filter as a bpf program."""
        cdef bpf_program fcode
        self.__compile(&fcode, value, optimize, netmask)
        # Python-ize the bpf_program. Note that this simply wraps the
        # buffer which pcap just allocated in the C library heap.
        pb = fasguard_pcap.bpf.progbuf(<object>&fcode, None)
        program = pb.__program__()
        return program

    cdef __compile(pcap self, bpf_program *fp, const char *s,
                   int optimize, unsigned int netmask):
        cdef int ret
        with nogil:
            ret = pcap_compile(self.__pcap, fp, s, optimize, netmask)
        if ret < 0:
            raise PcapError(errstr(self.geterr(), ret))

    def setdirection(self, pcap_direction_t value):
        """Set BPF capture direction."""
        cdef int ret
        with nogil:
            ret = pcap_setdirection(self.__pcap, value)
        if ret < 0:
            raise PcapError(errstr(self.geterr(), ret))

    def setnonblock(self, bint nonblock=True):
        """Set non-blocking capture mode."""
        with nogil:
            pcap_setnonblock(self.__pcap, nonblock, self.__ebuf)
    
    def getnonblock(self):
        """Return non-blocking capture mode as boolean."""
        cdef int ret
        with nogil:
            ret = pcap_getnonblock(self.__pcap, self.__ebuf)
        if ret < 0:
            raise PcapError(errstr(self.__ebuf, ret))
        elif ret:
            return True
        return False
    
    def datalink(self):
        """Return datalink type (DLT_* values)."""
        cdef int ret
        with nogil:
            ret = pcap_datalink(self.__pcap)
        return ret
    
    def next(self):
        """Return the next (header, packet) tuple, or None on error."""
        cdef pkthdr hdr = pkthdr(self.tstamp_precision)
        cdef const unsigned char *pkt
        with nogil:
            pkt = pcap_next(self.__pcap, &hdr.h)
        if not pkt:
            return None
        # TODO: figure out a way to mark the memorybuffer as invalid
        # on the next call to pcap_next_ex(), pcap_next(),
        # pcap_loop(), or pcap_dispatch()
        return (hdr,
                MemoryBuffer_init(<void *>pkt, hdr.caplen))

    def __add_pkts(self, ts, pkt, pkts):
        pkts.append((ts, pkt))
    
    def readpkts(self):
        """Return a list of (header, packet) tuples received in one buffer."""
        pkts = []
        self.dispatch(-1, self.__add_pkts, pkts)
        return pkts
    
    def dispatch(self, int cnt, callback, *args):
        """Collect and process packets with a user callback,
        return the number of packets processed, or 0 for a savefile.
        
        Arguments:
        
        cnt      -- number of packets to process;
                    or 0 to process all packets until an error occurs,
                    EOF is reached, or the read times out;
                    or -1 to process all packets received in one buffer
        callback -- function with (header, pkt, *args) prototype
        *args    -- optional arguments passed to callback on execution
        """
        cdef pcap_handler_ctx ctx = pcap_handler_ctx(callback, args, self)
        cdef int n

        # there's no need to increase ref count on ctx because
        # pcap_dispatch() doesn't hold onto ctx.  (once
        # pcap_dispatch() returns nothing will ever call the callback,
        # so the ref held during exection of this function is
        # sufficient to keep the object alive.)
        cdef unsigned char *arg = <unsigned char *><PyObject *>ctx
        with nogil:
            n = pcap_dispatch(self.__pcap, cnt, __pcap_handler, arg)
        if ctx.exc_info is not None:
            raise ctx.exc_info[0], ctx.exc_info[1], ctx.exc_info[2]
        return n

    def loop(self, callback, *args):
        """Loop forever, processing packets with a user callback.
        The loop can be exited with an exception, including KeyboardInterrupt.
        
        Arguments:

        callback -- function with (header, pkt, *args) prototype
        *args    -- optional arguments passed to callback on execution
        """
        cdef pkthdr hdr = pkthdr(self.tstamp_precision)
        cdef unsigned char *pkt
        cdef int n
        cdef MemoryBuffer pkt_mb
        with nogil:
            pcap_ex_setup(self.__pcap)
        while 1:
            with nogil:
                n = pcap_ex_next(self.__pcap, &hdr.h, &pkt)
            if n == 1:
                pkt_mb = MemoryBuffer_init(pkt, hdr.caplen)
                callback(hdr, pkt_mb, *args)
                pkt_mb.invalidate()
            elif n == -1:
                raise KeyboardInterrupt
            elif n == -2:
                break

    def breakloop(self):
        """Call pcap_breakloop() to break out of a packet processing loop.
        """
        with nogil:
            pcap_breakloop(self.__pcap)
    
    def inject(self, object packet not None):
        """Inject a packet onto an interface.
        May or may not work depending on platform.

        Arguments:

        packet -- a pointer to the packet in memory
        """
        if not PyObject_CheckBuffer(packet):
            raise TypeError("packet object must follow the buffer protocol")
        cdef int n
        cdef Py_buffer view
        PyObject_GetBuffer(packet, &view, PyBUF_SIMPLE)
        try:
            with nogil:
                n = pcap_inject(self.__pcap, view.buf, view.len)
        finally:
            PyBuffer_Release(&view)
        if (n < 0):
            raise PcapError(errstr(self.geterr(), n))

        return n

    def close(self):
        if self.__pcap:
            with nogil:
                pcap_close(self.__pcap)
            self.__pcap = NULL

    def geterr(self):
        """Return the last error message associated with this handle."""
        cdef char *ret
        with nogil:
            ret = pcap_geterr(self.__pcap)
        return ret
    
    def stats(self):
        """Return a 3-tuple of the total number of packets received,
        dropped, and dropped by the interface."""
        cdef pcap_stat pstat
        cdef int ret
        with nogil:
            ret = pcap_stats(self.__pcap, &pstat)
        if ret < 0:
            raise PcapError(errstr(self.geterr(), ret))
        return (pstat.ps_recv, pstat.ps_drop, pstat.ps_ifdrop)

    cpdef list_tstamp_types(self):
        cdef int ret
        cdef int *types
        cdef const char *name
        with nogil:
            ret = pcap_list_tstamp_types(self.__pcap, &types)
        if ret < 0:
            raise PcapError(errstr(self.geterr(), ret))
        try:
            type_list = []
            for x in types[:ret]:
                with nogil:
                    name = pcap_tstamp_type_val_to_name(x)
                type_list.append(<str>name)
            return type_list
        finally:
            with nogil:
                pcap_free_tstamp_types(types)

    cpdef ex_immediate(self):
        """disable buffering, if possible"""
        if self.__type != 'live':
            raise TypeError("immediate only makes sense for live captures")
        cdef int ret
        with nogil:
            ret = pcap_ex_immediate(self.__pcap)
        if ret < 0:
            raise PcapError("couldn't set BPF immediate mode")

    def __iter__(self):
        with nogil:
            pcap_ex_setup(self.__pcap)
        return self

    def __next__(self):
        cdef pkthdr hdr = pkthdr(self.tstamp_precision)
        cdef unsigned char *pkt
        cdef int n
        while 1:
            with nogil:
                n = pcap_ex_next(self.__pcap, &hdr.h, &pkt)
            if n == 1:
                # TODO: figure out a way to mark the memorybuffer as
                # invalid on the next call to pcap_next_ex(),
                # pcap_next(), pcap_loop(), or pcap_dispatch()
                return (hdr,
                        MemoryBuffer_init(pkt, hdr.caplen))
            elif n == -1:
                raise KeyboardInterrupt
            elif n == -2:
                raise StopIteration

    def __enter__(pcap self):
        return self

    def __exit__(pcap self, exc_type, exc_value, traceback):
        self.close()
    
    def __dealloc__(self):
        self.close()

cdef class pkthdr:
    cdef int _precision
    cdef pcap_pkthdr h
    def __cinit__(self, precision, time_t sec=0, suseconds_t usec_or_nsec=0,
                  unsigned int caplen=0, unsigned int len=0):
        if precision != PCAP_TSTAMP_PRECISION_MICRO \
           and precision != PCAP_TSTAMP_PRECISION_NANO:
            raise ValueError(
                'only microsecond and nanosecond precisions are supported')
        self._precision = precision
        self.h.ts.tv_sec = sec
        self.h.ts.tv_usec = usec_or_nsec
        self.h.caplen = caplen
        self.h.len = len
    property precision:
        def __get__(self):
            return self._precision
        def __set__(self, value):
            # convert the value from one precision to another
            if self._precision == value:
                return
            if value == PCAP_TSTAMP_PRECISION_MICRO:
                self.h.ts.tv_usec /= 1000
            elif value == PCAP_TSTAMP_PRECISION_NANO:
                self.h.ts.tv_usec *= 1000
            else:
                raise ValueError(
                    'only microsecond and nanosecond precisions are supported')
            self._precision = value
    property sec:
        def __get__(self):
            return self.h.ts.tv_sec
        def __set__(self, value):
            self.h.ts.tv_sec = value
    property nsec:
        def __get__(self):
            if self._precision == PCAP_TSTAMP_PRECISION_NANO:
                return self.h.ts.tv_usec
            else:
                return self.h.ts.tv_usec * 1000
        def __set__(self, value):
            if self._precision == PCAP_TSTAMP_PRECISION_NANO:
                self.h.ts.tv_usec = value
            else:
                self.h.ts.tv_usec = value / 1000
    property caplen:
        def __get__(self):
            return self.h.caplen
        def __set__(self, value):
            self.h.caplen = value
    property len:
        def __get__(self):
            return self.h.len
        def __set__(self, value):
            self.h.len = value
    cpdef pkthdr copy(pkthdr self):
        return pkthdr(self._precision, self.h.ts.tv_sec, self.h.ts.tv_usec,
                      self.h.caplen, self.h.len)

cdef class dumper:
    cdef pcap_dumper_t *d
    cdef int tstamp_precision

    def __init__(self, pcap p, const char *fname):
        with nogil:
            self.d = pcap_dump_open(p.__pcap, fname)
        if self.d == NULL:
            raise PcapError(p.geterr())
        self.tstamp_precision = p.tstamp_precision

    cpdef dump(dumper self, object packet, pkthdr header=None):
        """Dump a packet to a previously opened save file.

        Arguments:

        packet -- the packet
        header -- a pcap header provided by the caller of type pkthdr
        """
        if self.d == NULL:
            raise PcapError("dumper is not open")
        if not PyObject_CheckBuffer(packet):
            raise TypeError("packet object must follow the buffer protocol")

        cdef pkthdr newheader
        cdef Py_buffer view
        PyObject_GetBuffer(packet, &view, PyBUF_SIMPLE)
        try:
            if header is None:
                header = pkthdr(self.tstamp_precision,
                                calendar.timegm(time.gmtime()), 0,
                                view.len, view.len)
            elif header.precision != self.tstamp_precision:
                newheader = header.copy()
                # convert precision
                newheader.precision = self.tstamp_precision
                header = newheader

            header.len = view.len
            with nogil:
                pcap_dump(<unsigned char *>self.d, &header.h,
                          <const unsigned char *>view.buf)
        finally:
            PyBuffer_Release(&view)

    cpdef close(dumper self):
        if self.d != NULL:
            with nogil:
                pcap_dump_close(self.d)
            self.d = NULL

    def __dealloc__(self):
        self.close()

    def __enter__(dumper self):
        return self

    def __exit__(dumper self, exc_type, exc_value, traceback):
        self.close()

def ex_name(char *foo):
    cdef char *ret
    with nogil:
        ret = pcap_ex_name(foo)
    return ret

def lookupdev():
    """Return the name of a network device suitable for sniffing."""
    cdef char *p,
    cdef char ebuf[PCAP_ERRBUF_SIZE]
    with nogil:
        p = pcap_ex_lookupdev(ebuf)
    if p == NULL:
        raise PcapError(ebuf)
    return p

