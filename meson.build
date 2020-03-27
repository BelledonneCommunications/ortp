project('ortp', ['c' , 'cpp'], version : '4.4.0')
#get mbedtls libraries from the system:

threads = dependency('threads')

headers = [
	'include/ortp/rtcp.h',
	'include/ortp/rtpprofile.h',
	'include/ortp/rtp.h',
	'include/ortp/port.h',
	'include/ortp/event.h',
	'include/ortp/payloadtype.h',
	'include/ortp/rtpsignaltable.h',
	'include/ortp/b64.h',
	'include/ortp/nack.h',
	'include/ortp/logging.h',
	'include/ortp/ortp.h',
	'include/ortp/sessionset.h',
	'include/ortp/utils.h',
	'include/ortp/str_utils.h',
	'include/ortp/rtpsession.h',
	'include/ortp/telephonyevents.h',
	'include/MSVC/stdint.h',
	'include/MSVC/inttypes.h'
	]

src = [ 
	'src/rtpparse.c',
	'src/scheduler.c',
	'src/payloadtype.c',
	'src/congestiondetector.c',
	'src/rtcp_fb.c',
	'src/logging.c',
	'src/rtpbundle.cc',
	'src/rtpsession.c',
	'src/rtcp.c',
	'src/netsim.c',
	'src/rtcp_xr.c',
	'src/extremum.c',
	'src/rtptimer.c',
	'src/nack.c',
	'src/winrttimer.h',
	'src/videobandwidthestimator.h',
	'src/ortp.c',
	'src/kalmanrls.c',
	'src/utils.c',
	'src/videobandwidthestimator.c',
	'src/telephonyevents.c',
	'src/rtpprofile.c',
	'src/rtpbundle.h',
	'src/port.c',
	'src/rtptimer.h',
	'src/jitterctl.h',
	'src/sessionset.c',
	'src/posixtimer.c',
	'src/utils.h',
	'src/rtpsession_priv.h',
	'src/str_utils.c',
	'src/b64.c',
	'src/event.c',
	'src/avprofile.c',
	'src/scheduler.h',
	'src/rtpsignaltable.c',
	'src/rtpsession_inet.c',
	'src/jitterctl.c',
	'src/rtcpparse.c',
	'src/congestiondetector.h'
	]

incdirs = include_directories('include')

bctoolbox_dep = dependency('bctoolbox', fallback : ['bctoolbox', 'bctoolbox_dep'])

version_splitted = meson.project_version().split('.')
cc = meson.get_compiler('c')

#generation of the config.h:
configuration_data_object = configuration_data()
configuration_data_object.set('ORTP_VERSION' , '"' + meson.project_version() + '"')
configuration_data_object.set('ORTP_MAJOR_VERSION', version_splitted[0] )
configuration_data_object.set('ORTP_MINOR_VERSION', version_splitted[1] )
configuration_data_object.set('ORTP_MICRO_VERSION', version_splitted[2] )
configuration_data_object.set('HAVE_RECVMSG', cc.has_function('recvmsg') )
configuration_data_object.set('HAVE_SENDMSG', cc.has_function('sendmsg') )
configuration_data_object.set('POSIXTIMER_INTERVAL', 10000 )

configure_file(output : 'ortp-config.h',
               configuration : configuration_data_object)

#ortp compilation:
ortp_library = build_target('ortp', src,
	c_args : ['-DHAVE_CONFIG_H', '-D__APPLE_USE_RFC_3542'],
	dependencies : [ bctoolbox_dep, threads],  
	include_directories : [ incdirs, 'src'],
	target_type : 'both_libraries',
	install : true)

install_headers(headers, subdir : 'ortp')

specfile_config = configuration_data()
specfile_config.set('version' , meson.project_version())
configure_file(input : 'ortp.spec.in',
               output : 'ortp.spec',
               configuration: specfile_config,
               install : true,
               install_dir : 'share/SPECS')

#export ortp as a dependency.

ortp_dep = declare_dependency(include_directories : incdirs, link_with : ortp_library)


