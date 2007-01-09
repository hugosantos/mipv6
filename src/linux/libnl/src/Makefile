#
# src/Makefile
#
#		This program is free software; you can redistribute it and/or
#		modify it under the terms of the GNU General Public License
#		as published by the Free Software Foundation; either version
#		2 of the License, or (at your option) any later version.
#
# Copyright (c) 2003-2005 Thomas Graf <tgraf@suug.ch>
#
ifeq ($(shell [ ! -r ../Makefile.opts ] && echo 1),)
    include ../Makefile.opts
endif

CFLAGS	+= -L../lib
CIN 	:= $(wildcard nl-*.c)
TOOLS	:= $(CIN:%.c=%)

all: $(TOOLS)

$(TOOLS): utils.o

nl-%: nl-%.c
	$(CC) $(CFLAGS) -o $@ $< -lnl utils.o

clean:
	rm -f $(TOOLS) utils.o

distclean: clean

install:
	@true
