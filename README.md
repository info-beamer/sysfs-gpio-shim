#  Reviving /sys/class/gpio using FUSE

This FUSE based virtual filesystem emulates the deprecated
[/sys/class/gpio method](https://github.com/torvalds/linux/blob/7efd0a74039fb6b584be2cb91c1d0ef0bd796ee1/Documentation/userspace-api/gpio/sysfs.rst) of manipulating GPIOs. I wrote this
tool to see if it is possible to maintain backwards
compatibility for code deployed on a number of Raspberry Pis.

This code is still work in progress and should not be
considered stable.

While the new method using gpiod is really powerful, the
simplicity of just poking around in a few files is
sometimes still hard to beat.

## Compiling

I only tested on Raspberry Pi OS. Compiling requires
libfuse3-dev and unfortunately libgpiod 2.1 which Raspberry Pi
Bookworm currently doesn't ship. They still have 1.6.

So you'll have to compile [libgpiod 2.1 from source](https://git.kernel.org/pub/scm/libs/libgpiod/libgpiod.git/tree/README) first.
Once that's done, just type `make` and you should get the `sysfs-gpio-shim` binary.

## Running

Not sure how to best automate this on Raspberry Pi OS.
Manually it works like this. As root:

```
GPIO_GID="$(cut -d: -f3 < <(getent group gpio))"
./sysfs-gpio-shim -o default_permissions,allow_other,gid=$GPIO_GID /sys/class/gpio
```

This will shadow the existing /sys/class/gpio directory
with the emulated filesystem provided by this tool.

If you're done and no one is using the files in
`/sys/class/gpio` you can unmount the filesystem as
usual using `umount /sys/class/gpio`.

## What works/doesn't work

I only tried a simple push button connected to
GPIO18 on a Pi5 as well as some tests using multiple GPIOs
on a Pi3. Edge detection by polling /value should work.

Setting active low, setting or reading the current value and
exporting/unexporting the GPIO works too.

The behaviour should be mostly identical to what the
sysfs implementation did. See also TODO.md.

Non-Pi devices are not supported and no effort will
be made by me to change this. Sorry.

## Performance

Probably garbage. If you're using sysfs-based GPIO
control and expect performance, you're doing it wrong.

## Bugs/Help

If you find a bug, feel free to open an issue. If you
use this tool and it works well, please also let me
know :)
