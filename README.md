[![pipeline status](https://gitlab.linphone.org/BC/public/ortp/badges/master/pipeline.svg)](https://gitlab.linphone.org/BC/public/ortp/commits/master)

oRTP
====


oRTP is a C library implementing the RTP protocol (rfc3550). It is available
for most unix clones (primilarly Linux and HP-UX), and Microsoft Windows.

For additional information, please [visit oRTP's homepage on **linphone.org**](http://www.linphone.org/technical-corner/ortp).


License
-------

Copyright © Belledonne Communications

oRTP is dual licensed, and is available either :

 - under a [GNU/GPLv3 license](https://www.gnu.org/licenses/gpl-3.0.en.html), for free (open source). Please make sure that you understand and agree with the terms of this license before using it (see LICENSE.txt file for details).

 - under a proprietary license, for a fee, to be used in closed source applications. Contact [Belledonne Communications](https://www.linphone.org/contact) for any question about costs and services.

Prior to version 1.0.0, oRTP was licensed under LGPLv2. Due to inclusion of new code licensed under GPLv2, oRTP has become GPLv2,
and later in version 1.1.0, GPLv3.
For the sake of clarity, all source files headers were updated to mention the GPLv3 only.
oRTP versions prior to 1.0.0 of course remain LGPLv2.


Dependencies
------------

*bctoolbox[1]*: portability layer


Compilation
-----------

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

Rpm packaging
ortp rpm can be generated with cmake3 using the following command:
mkdir WORK
cd WORK
cmake3 ../
make package_source
rpmbuild -ta --clean --rmsource --rmspec ortp-<version>-<release>.tar.gz


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



----------------------------------------


[1] git://git.linphone.org/bctoolbox.git *or* <http://www.linphone.org/releases/sources/bctoolbox>
