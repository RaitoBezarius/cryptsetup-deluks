moduledir = $(libdir)/cryptsetup

noinst_LTLIBRARIES = libdeluks1.la

libdeluks1_la_CFLAGS = -Wall $(AM_CFLAGS) @CRYPTO_CFLAGS@

libdeluks1_la_SOURCES = \
	keymanage.c \
	keyencryption.c \
	deluks.h

AM_CPPFLAGS = -include config.h \
        -I$(top_srcdir)/lib			\
        -I$(top_srcdir)/lib/crypto_backend \
        -I$(top_srcdir)/lib/luks1

