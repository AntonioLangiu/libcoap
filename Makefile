SRCS = src/pdu.c src/net.c src/debug.c src/encode.c src/uri.c src/subscribe.c src/resource.c
SRCS += src/str.c src/option.c src/async.c src/block.c src/mem.c src/coap_io.c src/session.c

# set include path for coap sources
CFLAGS += -I$(libcoap_dir)/include/coap

OBJS=$(subst .c,.o,$(SRCS))

.o: %.c 
    $(CC) $(CFLAGS) $(CPPFLAGS) -c $<

all: $(OBJS)
