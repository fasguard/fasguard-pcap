#
# Author: George V. Neville-Neil
#
# Makefile for building distributions of fasguard-pcap.

PYTHON	= python2.7    #
CYTHON  = cython-2.7   # These versions are set for Mac OS Only

#PYTHON	= python
#CYTHON  = cython

all: 
	$(PYTHON) setup.py config
	$(PYTHON) setup.py build

install: all
	$(PYTHON) setup.py install

dist:
	$(PYTHON) setup.py sdist

clean:
	$(PYTHON) setup.py clean
	rm -rf build dist MANIFEST \
		fasguard_pcap/__init__.c \
		fasguard_pcap/bpf.c \
		fasguard_pcap/memorybuffer.c
