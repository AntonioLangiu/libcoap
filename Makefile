SRCS = src/pdu.c src/net.c src/debug.c src/encode.c src/uri.c src/subscribe.c src/resource.c
SRCS += src/str.c src/option.c src/async.c src/block.c src/mem.c src/coap_session.c src/coap_time.c
SRCS += src/coap_io_riot.c src/coap_notls.c src/address.c

# set include path for coap sources
CFLAGS += -Iinclude/coap -I. $(INCLUDES)

OBJS=$(subst .c,.o,$(SRCS))

%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS)

$(BINDIR)/libcoap.a: $(OBJS)
	$(AR) -rsv $@ $(OBJS)
	$(RANLIB) -t $@

clean:
	rm -f $(OBJS)
