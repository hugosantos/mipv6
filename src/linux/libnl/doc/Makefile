#
# doc/Makefile
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

export

.PHONY: all gendoc clean distclean install

all:
	@true

gendoc:
	doxygen Doxyfile

clean:
	@true

distclean:
	$(RM) -f html/*

install:
	@true

$(DEPS): ../Makefile.opts
