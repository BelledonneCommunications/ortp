# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]


## [1.1.0] - 2019-09-18

### Added
- Immediate NACK handling, to handle retransmission of lost packets.

### Changed
- License is now GNU GPLv3.



## [1.0.0] - 2017-01-10

### Added
- new adaptive jitter buffer algorithm, with improved performance.

### Changed
- License is changed from LGPLv2 to GPLv2.



## [0.27.0] - 2016-06-01

### Changed
- bctoolbox is added as dependency.

### Fixed
- DSCP handling on Windows.
- IPv6 handling for Windows and Android.


## [0.25.0] - 2015-11-02

### Added
- AVPF generic NACK
- Payload type definitions for real time text and codec2.

### Fixed
- Various things.


## [0.24.1] - 2015-05-31

### Added
- TMMBR and TMMBN handling (RFC5104).


## [0.24.0] - 2015-03-11

### Added
- RTCP send algorithm as describe in RFC3550.
- RTCP XR (RFC3611).
- RTCP send algorithm for AVPF streams as described in RFC4585.



## [0.23.0] - 2014-02-19

### Changed
- network simulator improvements.
- updated to use ZRTPCPP>=4

### Fixed
- security issues.
	

## [0.22.0] - 2012-05-27

### Changed
- Network simulator improvements for simulating random lost packets.

### Fixed
- SRTP initialization.

	
## [0.19.0] - 2012-02-17

### Added
- ZRTP media encryption.


## [0.18.0] - 2011-12-22

### Added
- SRTP media encryption


## [0.17.0] - 2011-05-??

### Added
- rtp_session_get_round_trip_propagation()

### Fixed
- RTCP support.


## [0.16.0] - 2010-05-10

### Added
- DSCP handling on Windows.
- Accessors to struct PayloadType.
- new payload type definitions.

### Changed
- update stun api to support new RFC.

### Fixed
- gcc warnings.


## [0.15.0] - 2008-10-13

### Changed
- reduce number of memory allocation: !! attention here ABI/API change !!
		If you are using mp=rtp_session_recvm_with_ts(), the payload data is no more pointed by mp->b_cont->b_rptr.
		Instead you can use the following to skip the header:
			rtp_get_payload(mp,mp->b_rptr);

### Fixed
- telephone event presence detection bug.


## [0.14.3] - 2008-03-14

### Added
- new ortp_set_memory_functions() method.

### Changed
- jitter buffer simplification and improvements


## [0.14.0] - 2007-07-27

### Added
- Number of channels in PayloadType (interface changed !).
- srtp optional support (using libsrtp from http://srtp.sf.net)

### Changed
- optimisations.


## [0.13.1] - 2007-04-11

### Changed
- do not recv rtcp packets from rtp_session_sendm_with_ts() when session is not send-only.
- removed gtk-doc, using doxygen instead.


## [0.13.0] - 2007-01-23

### Added
- new telephone-event types.
- pluggable transport layer.

### Changed
- enables use of different RtpProfile for send and recv directions.

### Fixed
- RTCP memory leak.


## [0.12.0] - 2006-11-09

### Added
- enable 0 ms jitter buffer (implies permissive dequeuing of packets).
- enable optional connected mode: the udp socket is connect()ed so only 
	  packets coming from the connected destination are received.

### Changed
- jitter buffer accuracy improved.

### Fixed
- statistics.


## [0.11.0] - 2006-08-22

### Added
- rtp_session_set_dscp(), rtp_session_send_rtcp_APP().

### Fixed
- statistics.


## [0.10.0] - 2006-05-30

### Added
- new RTCP parser
- new event api
- stun helper routines
- permissive algorithm for video packet enqueueing


