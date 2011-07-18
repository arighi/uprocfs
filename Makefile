TOPDIR=$(shell /bin/pwd)
TARGET=uproc
OBJS=src/uproc.o
CFLAGS=-g -O2 -Wall `pkg-config fuse --cflags` -I$(TOPDIR)/include -DPAGE_SIZE=`getconf PAGE_SIZE`
LDFLAGS=`pkg-config fuse --libs`

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
