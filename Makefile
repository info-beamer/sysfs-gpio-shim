CFLAGS  += -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE=1 -std=gnu99 -Wall \
           $(shell pkg-config fuse3 --cflags) \
           $(shell pkg-config libgpiod --cflags)

LDFLAGS += $(shell pkg-config fuse3 --libs) \
           $(shell pkg-config libgpiod --libs)

all: sysfs-gpio-shim

sysfs-gpio-shim: sysfs-gpio-shim.c
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

# Meh
sysfs-gpio-shim.static: sysfs-gpio-shim.c
	arm-linux-musleabihf-gcc $(CFLAGS) $^ libfuse3.a libgpiod.a -static -o $@
	strip $@

clean:
	rm -f sysfs-gpio-shim sysfs-gpio-shim.static

.PHONY: clean
