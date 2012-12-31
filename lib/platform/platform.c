
#if defined ( __linux__ )
#	include "sys_linux.c"
#	warning "PLATFORM: LINUX"
#	ifndef SYS_LINUX
#		define SYS_NT 1
#	endif
#elif ( (!defined(__linux__)) && ((defined(__unix__)) || (defined(__APPLE__) && defined(__MACH__))) )
#	include "sys_bsd.c"
#	warning "PLATFORM: BSD"
#	ifndef SYS_BSD
#		define SYS_BSD 1
#	endif
#elif ( defined(_WIN32) || defined(_WIN64) )
#	include "sys_nt.c"
#	warning "PLATFORM: NT"
#	ifndef SYS_NT
#		define SYS_NT 1
#	endif
#else
#error	"PLATFORM: UNKNOWN"
#endif

