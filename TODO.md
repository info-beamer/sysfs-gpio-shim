 * Stop epoll'ing edges if no one is polling on /value.

 * Examine what the default state of lines is. This tool
   always sets the line direction to input after 'export'.

 * Make sure reading and writing from the individual gpio files is the same
   as the original sysfs interface:

   * Writing:
       * Kernel seems to accept writes to any offset within the file.
       * All data must be within a single write call.
       * Can optionally end with a '\n'

   * Reading:
       * A seek to 0 seems to switch to the next output buffer.
       * Reading individual bytes reads out potentially stale data:

         ```
         import os
         fd = os.open("/sys/class/gpio/gpio520/edge", os.O_RDWR)
         os.lseek(fd, 0, 0)
         os.write(fd, b"falling")
         os.lseek(fd, 0, 0)
         print(os.read(fd, 2))  # "fa"
         os.lseek(fd, 0, 0)
         os.write(fd, b"rising")
         os.lseek(fd, 2, 0)
         print(os.read(fd, 2))  # "ll"
         os.lseek(fd, 2, 0)
         print(os.read(fd, 2))  # "ll"
         os.lseek(fd, 0, 0)
         print(os.read(fd, 10)) # "rising"
         ```
 * Chown or similar are not supported at the moment. You can only
   set permissions using the `-o uid=XXX` and `-o gid=XXX` parameters
   when starting the tool. Using `-o default_permissions,allow_other`
   seems useful for that.
