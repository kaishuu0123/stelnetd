BIN=stelnetd
SRCS=$(BIN).c
OBJS=$(BIN).o

CFLAGS= -Wall -g
LDFLAGS=

all: $(BIN)

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

$(BIN): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)

clean:
	rm -f $(OBJS) $(BIN)
