

# connect - tiny cross-platform library for sockets routine


##  Content

	README   -  this file  
	docs     -  documents and links  
	junk     -  old legacy files  
	samples  -  snippets and demo code  
		netlink  -  GNU/Linux netlink sockets  
		raw      -  raw sockets  
		winsock  -  Winsock sockets  


##  Source library content

	connect.gm  -  GNU Make file for build on BSD/OSX/GNU/Linux  
	connect.nm  -  MS NMake file for build on Windows  
	src         -  demo code for using library  
	lib         -  core library tree  
		routine.*  -  routine functions  
		platform   -  cross-platform detection routine  
		socket     -  sockets routine  
		raw        -  raw sockets routine  
		netlink    -  netlink GNU/Linux sockets  


## Headers tree

	lib/platform/api_bsd.h  -  header file for BSD sockets     : includes section only;  
	lib/platform/api_nt.h   -  header file for Winsock sockets : includes section only;  
		lib/platform/connect.h  -  detect platfrom and then includes related header; defines cross platform routine macros; includes routine header;  
				lib/routine.h  -  cross platform routine helper functions; body of header are divided by supported platforms;  
				lib/routine.c  -  includes connect.h;  
				lib/socket/tcp.h  -  TCP-related socket routine; cross platform; includes connect header;  


## Direct header tree (legacy)

connect app:  
  include platform/connect.h  <---  (api_bsd || api_nt) && routine  
  include socket/tcp.h        <---  platform/connect.h  

connect app (easy way):  
connect app:  
  include (lib)/connect.h  <---  platform/connect.h socket/tcp.h ...  


