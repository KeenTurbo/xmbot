CFLAGS = -O2 -g -I/home/wgjtyu/others/openwrt-git/backfire/staging_dir/target-mips_uClibc-0.9.30.1/usr/include/
CFLAGS += -Wall --std=gnu99
LDFLAGS = -liksemel -L /home/wgjtyu/others/openwrt-git/backfire/staging_dir/target-mips_uClibc-0.9.30.1/usr/lib

all: xmbot

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $^

xmbot: main.o
	$(CC) $(LDFLAGS) -g -o $@ $^ $(LIBS)
