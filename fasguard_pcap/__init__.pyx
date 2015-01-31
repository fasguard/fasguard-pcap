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

from cpython.ref cimport PyObject
from posix.time cimport timeval
import sys
import calendar
import time

from cpython.oldbuffer cimport PyBuffer_FromMemory

cimport fasguard_pcap.bpf
import fasguard_pcap.bpf

from fasguard_pcap.bpf cimport bpf_insn
from fasguard_pcap.bpf cimport bpf_program

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
    pcap_t *pcap_open_offline(char *fname, char *errbuf)
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
    cdef enum:
        PCAP_ERRBUF_SIZE

cdef extern from "pcap_ex.h" nogil:
    int     pcap_ex_immediate(pcap_t *p)
    char   *pcap_ex_name(char *name)
    void    pcap_ex_setup(pcap_t *p)
    int     pcap_ex_next(pcap_t *p, pcap_pkthdr **hdr,
                         unsigned char **pkt)
    char   *pcap_ex_lookupdev(char *errbuf)

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

cdef void __pcap_handler(unsigned char *arg, const pcap_pkthdr *hdr,
                         const unsigned char *pkt) with gil:
    cdef pcap_handler_ctx ctx = <pcap_handler_ctx><PyObject *>arg
    if ctx.exc_info is not None:
        # don't want to risk raising another exception, so we'll wait
        # until pcap_breakloop() does its thing
        return
    try:
        ctx.callback(hdr.ts.tv_sec + (hdr.ts.tv_usec/1000000.0),
                     PyBuffer_FromMemory(<void *>pkt, hdr.caplen),
                     *ctx.args)
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
    cdef bpf_program prog
    cdef int rc
    prog.bf_len = 0
    prog.bf_insns = NULL
    with nogil:
        rc = pcap_compile_nopcap(snaplen, dlt, &prog, str, optimize, netmask)
    if rc == -1:
        raise OSError
    # Python-ize the bpf_program. Note that this simply wraps the buffer
    # which pcap just allocated in the C library heap.
    pb = fasguard_pcap.bpf.progbuf(<object> &prog, None)
    program = pb.__program__()
    return program

cdef class pcap:
    """Handle to a packet capture descriptor.

    Attributes:
        filter
            Current packet capture filter.
        name
            Network interface or dumpfile name.
    """
    cdef pcap_t *__pcap
    cdef readonly bytes name
    cdef readonly bytes filter
    cdef char __ebuf[PCAP_ERRBUF_SIZE]
    cdef pcap_dumper_t *__dumper

    @staticmethod
    def open_dead(int linktype, int snaplen):
        """Open a handle to a packet capture descriptor.

        Keyword arguments:
        linktype  -- link-layer type
        snaplen   -- maximum number of bytes to capture for each packet
        """
        ret = pcap()
        with nogil:
            ret.__pcap = pcap_open_dead(linktype, snaplen)
        if ret.__pcap == NULL:
            raise OSError("error in pcap_open_dead()")
        return ret

    @staticmethod
    def open_offline(const char *fname):
        """Open a handle to a packet capture descriptor.

        Keyword arguments:
        fname     -- name of a dumpfile to open
        """
        ret = pcap()
        with nogil:
            ret.__pcap = pcap_open_offline(fname, ret.__ebuf)
        if ret.__pcap == NULL:
            raise OSError(ret.__ebuf)
        ret.name = fname
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
            raise OSError(ret.__ebuf)
        ret.name = device
        return ret

    property snaplen:
        """Maximum number of bytes to capture for each packet."""
        def __get__(self):
            cdef int ret
            with nogil:
                ret = pcap_snapshot(self.__pcap)
            return ret
        
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
            raise ValueError, ""
        # cast to temporary required.
        pbp = fasguard_pcap.bpf.program.__progbuf__(bpfprogram)
        bp = fasguard_pcap.bpf.progbuf.__bpf_program__(pbp)
        self.__setfilter(bp)

    cdef void __setfilter(pcap self, bpf_program *fp):
        cdef int ret
        with nogil:
            ret = pcap_setfilter(self.__pcap, fp)
        if ret < 0:
            raise OSError, self.geterr()

    def compile(self, const char *value, bint optimize=True,
                unsigned int netmask=0):
        """Compile a filter expression to a BPF program for this pcap.
           Return the filter as a bpf program."""
        cdef bpf_program fcode
        self.__compile(&fcode, value, optimize, netmask)
        pb = fasguard_pcap.bpf.progbuf(<object>&fcode, None)
        program = pb.__program__()
        return program

    cdef __compile(pcap self, bpf_program *fp, const char *s,
                   int optimize, unsigned int netmask):
        cdef int ret
        with nogil:
            ret = pcap_compile(self.__pcap, fp, s, optimize, netmask)
        if ret < 0:
            raise OSError, self.geterr()

    def setdirection(self, pcap_direction_t value):
        """Set BPF capture direction."""
        cdef int ret
        with nogil:
            ret = pcap_setdirection(self.__pcap, value)
        if ret < 0:
            raise OSError, self.geterr()

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
            raise OSError, self.__ebuf
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
        """Return the next (timestamp, packet) tuple, or None on error."""
        cdef pcap_pkthdr hdr
        cdef const unsigned char *pkt
        with nogil:
            pkt = pcap_next(self.__pcap, &hdr)
        if not pkt:
            return None
        return (hdr.ts.tv_sec + (hdr.ts.tv_usec / 1000000.0),
                PyBuffer_FromMemory(pkt, hdr.caplen))

    def __add_pkts(self, ts, pkt, pkts):
        pkts.append((ts, pkt))
    
    def readpkts(self):
        """Return a list of (timestamp, packet) tuples received in one buffer."""
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
        callback -- function with (timestamp, pkt, *args) prototype
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

        callback -- function with (timestamp, pkt, *args) prototype
        *args    -- optional arguments passed to callback on execution
        """
        cdef pcap_pkthdr *hdr
        cdef unsigned char *pkt
        cdef int n
        with nogil:
            pcap_ex_setup(self.__pcap)
        while 1:
            with nogil:
                n = pcap_ex_next(self.__pcap, &hdr, &pkt)
            if n == 1:
                callback(hdr.ts.tv_sec + (hdr.ts.tv_usec / 1000000.0),
                         PyBuffer_FromMemory(pkt, hdr.caplen), *args)
            elif n == -1:
                raise KeyboardInterrupt
            elif n == -2:
                break

    def breakloop(self):
        """Call pcap_breakloop() to break out of a packet processing loop.
        """
        with nogil:
            pcap_breakloop(self.__pcap)
    
    def inject(self, packet, len):
        """Inject a packet onto an interface.
        May or may not work depending on platform.

        Arguments:

        packet -- a pointer to the packet in memory
        """
        cdef int n
        cdef size_t packet_len = len(packet)
        cdef const unsigned char *packet_c = packet
        with nogil:
            n = pcap_inject(self.__pcap, packet_c, packet_len)
        if (n < 0):
            raise OSError, self.geterr()

        return n
    
    def dump(self, packet, header=None):
        """Dump a packet to a previously opened save file.

        Arguments:

        packet -- the packet
        header -- a pcap header provided by the caller
        A user supplied header MUST contain the following fields
            header.sec: The timestamp in seconds from the Unix epoch
            header.usec: The timestamp in micro seconds
            header.caplen: Length of packet present
            header.len: Total length of packet
        """
        if self.__dumper == NULL:
            raise OSError("dumper is not open")
        cdef pcap_pkthdr hdr
        if header != None:
            hdr.ts.tv_sec = header.sec
            hdr.ts.tv_usec = header.usec
            hdr.caplen = header.caplen
            hdr.len = len(packet)
        else:
            hdr.ts.tv_sec = calendar.timegm(time.gmtime())
            hdr.ts.tv_usec = 0
            hdr.caplen = len(packet)
            hdr.len = len(packet)

        cdef const unsigned char *packet_c = packet
        with nogil:
            pcap_dump(<unsigned char *>self.__dumper, &hdr, packet_c)

    def dump_close(self):
        if self.__dumper != NULL:
            with nogil:
                pcap_dump_close(self.__dumper)
            self.__dumper = NULL

    def dump_open(const char *fname):
        if self.__dumper != NULL:
            raise OSError("dumper already open")
        with nogil:
            self.__dumper = pcap_dump_open(self.__pcap, fname)
        if not self.__dumper:
            raise OSError, self.geterr()

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
            raise OSError, self.geterr()
        return (pstat.ps_recv, pstat.ps_drop, pstat.ps_ifdrop)

    cdef void ex_immediate(self):
        """disable buffering, if possible"""
        cdef int ret
        with nogil:
            ret = pcap_ex_immediate(self.__pcap)
        if ret < 0:
            raise OSError, "couldn't set BPF immediate mode"

    def __iter__(self):
        with nogil:
            pcap_ex_setup(self.__pcap)
        return self

    def __next__(self):
        cdef pcap_pkthdr *hdr
        cdef unsigned char *pkt
        cdef int n
        while 1:
            with nogil:
                n = pcap_ex_next(self.__pcap, &hdr, &pkt)
            if n == 1:
                return (hdr.ts.tv_sec + (hdr.ts.tv_usec / 1000000.0),
                        PyBuffer_FromMemory(pkt, hdr.caplen))
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
        raise OSError, ebuf
    return p

