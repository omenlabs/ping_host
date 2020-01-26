#
# Compiled on IRIX 6.2 using The MIPSpro C Compiler 
#
# libpcap is courtesy of tgcware.
#
# https://jupiterrise.com/tgcware/tgcware.irix.html
# http://tgcware.irixnet.org
#
#
# You will need to make sure the dmedia sw32 eoe and dev
# libs are installed.  The default ABI is o32 on IRIX 6.2, but
# tgcware is compiled n32.
#
# See http://www.sgistuff.net/software/irixintro/documents/irix6.2TR.html#HDR39

CC = cc
CFLAGS = -O -n32 -I/usr/tgcware/include 
LDFLAGS = 
SHELL = /bin/sh

all: ping_host

ping_host: ping_host.o
	$(CC) $(CFLAGS) ping_host.o -o $@ -laudio -laudiofile -laudioutil -L/usr/tgcware/lib -lpcap

clean:
	-rm -f *.o
	-rm ping_host
