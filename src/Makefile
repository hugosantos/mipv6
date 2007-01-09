CC		?= gcc
ARCHIVE		?= ar

CFLAGS		?= -Wall -Wshadow -Wpointer-arith \
		   -Wmissing-declarations -Wredundant-decls
CFLAGS		+= -D_GNU_SOURCE
INCLUDES	:= -I../include -I../include/system

GCC_VERSION	= 3.0
OS		= Linux

ifeq ($(GCC_VERSION),4.0)
	CFLAGS += -Wextra -Wno-unused-parameter -Wdeclaration-after-statement
endif

OPTIMIZE	?= no

ifeq ($(OPTIMIZE),yes)
	CFLAGS += -O3
else
	CFLAGS += -g -O0 -fno-inline
endif

LINKER		= $(CC)

ifeq ($(OS),Linux)
	OS_INCLUDES	:= -Ilinux/libnl/include
	OS_LDFLAGS	:= -Llinux/libnl/lib -lnl -lm

	LINKER		= $(CC) -rdynamic
endif

CFLAGS		+= $(OS_INCLUDES) $(INCLUDES)
LDFLAGS		+= $(OS_LDFLAGS) -lcrypto -lssl

MBLTY_SRCS	= debug.c timers.c heap.c support.c address.c \
		  autoconf.c events.c icmpv6.c interface.c ndisc.c \
		  prefix.c reach.c router.c tunnel.c

ifeq ($(OS),Linux)
	OS_SRCS	= linux/linux-os.c linux/linux-mngmnt.c \
		  linux/linux-xfrm.c
else
	ifeq ($(OS),Dummy)
		OS_SRCS = dummy/dummy-os.c dummy/dummy-mng.c
	endif
endif

MBLTY_SRCS	+= $(OS_SRCS)

MBLTY_LIB	= libmblty.a
MBLTY_LDFLAGS	= -L. -lmblty

ifeq ($(OS),Linux)
	LIBNL		= linux/libnl/lib/libnl.a
	MBLTY_DEPS	= $(LIBNL)
endif

MBLTY_OBJS	= $(MBLTY_SRCS:.c=.o)

PROTOCOL_SRCS	= conf.c rconsole.c protocol.c proto-cn.c \
		  proto-mn.c proto-rr.c proto-ipsec.c sec-openssl.c \
		  in_cksum.c ikev1-racoon1.c

ifeq ($(OS),Linux)
	PROTOCOL_SRCS += linux/linux-bcache.c
endif

PROTOCOL_LIB	= libmipv6base.a
PROTOCOL_LDFLAGS= -L. -lmipv6base

PROTOCOL_OBJS	= $(PROTOCOL_SRCS:.c=.o)

MN		= mipv6-mn
MN_SRCS		= mn.c mn-hoa.c mn-ro.c mn-rconsole.c mn-helper.c \
		  mn-dhaad.c rconsole-common.c
MN_OBJS		= $(MN_SRCS:.c=.o)

HA		= mipv6-ha
HA_SRCS		= ha.c ha-dhaad.c ha-rconsole.c rconsole-common.c
HA_OBJS		= $(HA_SRCS:.c=.o)

AR		= mob6-ar
AR_SRCS		= ar.c
AR_OBJS		= $(AR_SRCS:.c=.o)

MN_LIBS		= $(MBLTY_LIB) $(MBLTY_DEPS) $(PROTOCOL_LIB)
HA_LIBS		= $(MBLTY_LIB) $(MBLTY_DEPS) $(PROTOCOL_LIB)
AR_LIBS		= $(MBLTY_LIB) $(MBLTY_DEFS)

MN_LDFLAGS	= $(MBLTY_LDFLAGS) $(PROTOCOL_LDFLAGS) $(LDFLAGS)
HA_LDFLAGS	= $(MBLTY_LDFLAGS) $(PROTOCOL_LDFLAGS) $(LDFLAGS)
AR_LDFLAGS	= $(MBLTY_LDFLAGS) $(LDFLAGS)

# for dependencies
ALL_SOURCES	= $(MBLTY_SRCS) $(PROTOCOL_SRCS) $(MN_SRCS) $(HA_SRCS) $(AR_SRCS)
DEPENDENCIES	= $(ALL_SOURCES:%.c=.deps/%.d)

TARGETS		= $(MN) $(HA) $(AR)

all: $(TARGETS)

# -rdynamic is only used here to get decent results
#  from backtrace_symbols

$(MN): $(MN_LIBS) $(MN_OBJS)
	@echo " BUILD $(MN)"
	@$(LINKER) -o $(MN) $(MN_OBJS) $(MN_LDFLAGS)

$(HA): $(HA_LIBS) $(HA_OBJS)
	@echo " BUILD $(HA)"
	@$(LINKER) -o $(HA) $(HA_OBJS) $(HA_LDFLAGS)

$(AR): $(AR_LIBS) $(AR_OBJS)
	@echo " BUILD $(AR)"
	@$(LINKER) -o $(AR) $(AR_OBJS) $(AR_LDFLAGS)

$(MBLTY_LIB): $(MBLTY_OBJS)
	@echo " AR $(MBLTY_LIB)"
	@$(ARCHIVE) rs $(MBLTY_LIB) $(MBLTY_OBJS)

$(PROTOCOL_LIB): $(PROTOCOL_OBJS)
	@echo " AR $(PROTOCOL_LIB)"
	@$(ARCHIVE) rs $(PROTOCOL_LIB) $(PROTOCOL_OBJS)

$(LIBNL):
	$(MAKE) -C linux/libnl/lib

%.o: %.c
	@echo " CC $<"
	@$(CC) -c $(CFLAGS) $(INCLUDES) $< -o $@

clean:
	$(MAKE) -C linux/libnl/lib clean
	rm -rf $(MBLTY_OBJS) $(MBLTY_LIB) $(MN) $(MN_OBJS) $(HA) $(HA_OBJS) \
	       .deps *.tab.c *.tab.h mn-scanner.c ha-scanner.c \
	       $(PROTOCOL_LIB) $(PROTOCOL_OBJS)

.deps/%.d: %.c
	@echo " DEPS $<"
	@set -e; mkdir -p $(dir $@); \
	 $(CC) -MM -MT $@ -MT $(<:.c=.o) $(CFLAGS) $< > $@

ifneq ($(MAKECMDGOALS),clean)
-include $(DEPENDENCIES)
endif

.PHONY: clean
