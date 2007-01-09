#
# lib/Makefile
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

# Core
CIN      := $(wildcard *.c)
# NETLINK_ROUTE
CIN      += $(wildcard route/*.c)
# Schedulers
CIN      += $(wildcard route/sch/*.c)
# Classifiers
CIN      += $(wildcard route/cls/*.c)
# fib lookup
CIN      += $(wildcard fib_lookup/*.c)

DEPS     := $(CIN:%.c=.deps/%.d)
OBJ      := $(CIN:%.c=%.o)
CFLAGS   += -fPIC
OUT_AR   := $(PACKAGE_NAME).a
OUT_SLIB := $(PACKAGE_NAME).so.$(PACKAGE_VERSION)
LN_SLIB  := $(PACKAGE_NAME).so
LN1_SLIB := $(LN_SLIB).1

export

.PHONY: all clean install $(OUT_AR) $(OUT_SLIB)


all:
	@echo "  MAKE $(OUT_AR)"; \
	$(MAKE) $(OUT_AR)

$(OUT_AR): ../Makefile.opts $(OBJ)
	@echo "  AR $(OUT_AR)"
	@$(AR) rs $(OUT_AR) $(OBJ)

$(OUT_SLIB): ../Makefile.opts $(OBJ)
	@echo "  LD $(OUT_SLIB)"; \
	$(CC) -shared -Wl,-soname,libnl.so.1 -o $(OUT_SLIB) $(OBJ) $(LIBNL_LIB) -lc
	@echo "  LN $(OUT_SLIB) $(LN1_SLIB)"; \
	rm -f $(LN1_SLIB) ; $(LN) -s $(OUT_SLIB) $(LN1_SLIB)
	@echo "  LN $(LN1_SLIB) $(LN_SLIB)"; \
	rm -f $(LN_SLIB) ; $(LN) -s $(LN1_SLIB) $(LN_SLIB)

clean:
	@echo "  CLEAN lib"; \
	$(RM) -f $(OBJ) $(OUT_SLIB) $(LN_SLIB) $(LN1_SLIB); \
	$(RM) -f $(OUT_SLIB) $(LN_SLIB) $(LN1_SLIB)

distclean:
	find .deps -iname \*\.d -exec rm -f '{}' \;

install:
	mkdir -p $(DESTDIR)$(prefix)$(libdir)/
	install -o root -g root -m 0644 $(OUT_SLIB) $(DESTDIR)$(prefix)$(libdir)
	rm -f $(DESTDIR)$(prefix)$(libdir)/$(LN1_SLIB) ; \
	$(LN) -s $(OUT_SLIB) $(DESTDIR)$(prefix)$(libdir)/$(LN1_SLIB)
	rm -f $(DESTDIR)$(prefix)$(libdir)/$(LN_SLIB) ; \
	$(LN) -s $(LN1_SLIB) $(DESTDIR)$(prefix)$(libdir)/$(LN_SLIB)

$(DEPS): ../Makefile.opts

include ../Makefile.rules
