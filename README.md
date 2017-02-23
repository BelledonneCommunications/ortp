oRTP
====

What is it ?
------------

oRTP is a GPLv2 licensed C library implementing the RTP protocol (rfc3550). It is available
for most unix clones (primilarly Linux and HP-UX), and Microsoft Windows.

Prior to version 1.0.0, oRTP was licensed under LGPLv2. Due to inclusion of new code licensed under GPLv2, oRTP has become GPLv2.
For the sake of clarity, all source files headers were updated to mention the GPLv2 only.
oRTP versions prior to 1.0.0 of course remain LGPLv2.


What are the build prequisites ?
--------------------------------

*bctoolbox[1]*: portability layer


What build instructions
-----------------------

Autotools procedure is deprecated. Use CMake to configure the source code.

	cmake . -DCMAKE_INSTALL_PREFIX=<prefix> -DCMAKE_PREFIX_PATH=<search_paths>
	
	make
	make install

### Options:

- `CMAKE_INSTALL_PREFIX=<string>` : install prefix
- `CMAKE_PREFIX_PATH=<string>`    : column-separated list of prefixes where to search for dependencies
- `ENABLE_SHARED=NO`              : do not build the shared library
- `ENABLE_STATIC=NO`              : do not build the static library
- `ENABLE_STRICT=NO`              : build without strict compilation flags (-Wall -Werror)
- `ENABLE_TESTS=YES`              : build tester binaries
- `ENABLE_DOC=NO`                 : do not generate the documentation
- `ENABLE_DEBUG_LOGS=YES`         : turn on debug-level logs


### Note for packagers:

Our CMake scripts may automatically add some paths into research paths of generated binaries.
To ensure that the installed binaries are striped of any rpath, use `-DCMAKE_SKIP_INSTALL_RPATH=ON`
while you invoke cmake.


How do you I test ?
-------------------

There are shorts and easy to understand programs given with the library. There are good example
to understand how to use oRTP api.

- rtpsend : sends a stream from a file on disk.
- rtprecv : receives a stream and writes it to disk.
- mrtpsend: sends multiple streams from a file on disk to a range of remote port.
- mrtprecv:	receives mutiple streams on a range of local ports and writes them on disk.


Is there some documentation ?
-----------------------------

See the doxygen generated API documentation in docs/html. Program examples are a very good
starting point.


What are the current features ?
-------------------------------

- works with ipv6
- packet scheduler
- adaptive jitter compensation
- automatic sending of RTCP SR or RR coumpounded with a SDES
- RTCP parser API


What are the planned features ?
-------------------------------

- multi-endpoint rtp sessions.


In which application oRTP is being used ?
-----------------------------------------

- linphone (http://www.linphone.org) was the first.
- the OCMP platform (a Hewlett Packard product).


How to compile my program using ortp ?
--------------------------------------
gcc -o myprogram  `pkg-config --cflags ortp` myprogram.c  \
			`pkg-config --libs ortp`


What about Windows port ?
-------------------------
There are instructions and Microsoft Visual C++ project files in build/win32native/oRTP.


----------------------------------------


[1] git://git.linphone.org/bctoolbox.git *or* <http://www.linphone.org/releases/sources/bctoolbox>
