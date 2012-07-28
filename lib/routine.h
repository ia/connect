
#ifndef _ROUTINE_H_
#define _ROUTINE_H_

/* declarations - not for using outside directly */

void *get_in_addr(struct sockaddr *sa);
unsigned int get_in_port(struct sockaddr *sa);
int get_str_addr(struct addrinfo *node, char *addr);
int cnct_socket_sendall(socket_t sd, char *msg, int len, int flags);

/* *** */

#endif /* _ROUTINE_H_ */

