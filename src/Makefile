CFLAGS = -O2 -g
CFLAGS += -Wall --std=gnu99

all: xmbot

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $^

xmbot: main.o
	$(CC) $(LDFLAGS) -g -o $@ $^ $(LIBS)
