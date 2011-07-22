VERSION=0.2

TOPDIR=$(shell /bin/pwd)
TARGET=uproc
OBJS=src/uproc.o
CFLAGS=-g -O2 -Wall `pkg-config fuse --cflags` -I$(TOPDIR)/include
LDFLAGS=`pkg-config fuse --libs`

CFLAGS+=-DPAGE_SIZE=$(shell getconf PAGE_SIZE) -DCACHELINE_SIZE=$(shell getconf LEVEL1_DCACHE_LINESIZE) -DVERSION=$(VERSION)

ifeq ($(V),1)
  Q =
else
  Q = @
endif

all: $(TARGET)

%.o: %.c
	@echo CC  $<
	$(Q)$(CC) $(CFLAGS) -c -o $@ $<

$(TARGET): $(OBJS)
	@echo LD  $<
	$(Q)$(CC) $(LDFLAGS) $(OBJS) -o $(TARGET)

tags:
	@echo GEN  tags
	$(Q)ctags -R .

clean:
	@echo CLEAN
	$(Q)rm -f $(OBJS) $(TARGET) tags
