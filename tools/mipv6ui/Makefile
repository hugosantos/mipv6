GTKFLAGS=`pkg-config --cflags gtk+-2.0`
GTKLIBS=`pkg-config --libs gtk+-2.0`

MIPINCLUDES=-I../../include

CFLAGS=-Wall $(GTKFLAGS) $(MIPINCLUDES)
LDFLAGS=$(GTKLIBS)

PROGS=peer main

all: $(PROGS)

main: wireless.o interface.o tray.o eggtrayicon.o

clean:
	rm -rf *.o $(PROGS)
	
