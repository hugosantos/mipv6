#
# include/Makefile
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

.PHONY: all clean install 

all:
	@true

clean:
	@true

distclean:
	@true

install:
	mkdir -p $(DESTDIR)$(prefix)/include/netlink/route/sch/
	mkdir -p $(DESTDIR)$(prefix)/include/netlink/route/cls/
	mkdir -p $(DESTDIR)$(prefix)/include/netlink/fib_lookup/
	install -o root -g root -m 0644 netlink/*.h $(DESTDIR)$(prefix)/include/netlink/
	install -o root -g root -m 0644 netlink/route/*.h $(DESTDIR)$(prefix)/include/netlink/route/
	install -o root -g root -m 0644 netlink/route/sch/*.h $(DESTDIR)$(prefix)/include/netlink/route/sch/
	install -o root -g root -m 0644 netlink/route/cls/*.h $(DESTDIR)$(prefix)/include/netlink/route/cls/
	install -o root -g root -m 0644 netlink/fib_lookup/*.h $(DESTDIR)$(prefix)/include/netlink/fib_lookup/
