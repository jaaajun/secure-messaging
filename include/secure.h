#ifndef _SECURE_H_
#define _SECURE_H_

#include <sys/types.h>

/* due to block alignment, the return value is supposed to be len - len % 16 + 16 */
ssize_t secure_send(int channel, const void * buf, size_t len, int flags,
                    const unsigned char * key, const unsigned char * iv);
/* due to block alignment, the return value is supposed to be len - len % 16 + 16 */
ssize_t secure_recv(int channel, void * buf, size_t len, int flags,
                    const unsigned char * key, const unsigned char * iv);

int secure_server_init(void);
int secure_server_buildkey(int channel, unsigned char * key, unsigned char * iv);
void secure_server_finish(void);

int secure_client_init(void);
int secure_client_buildkey(int channel, unsigned char * key, unsigned char * iv);
void secure_client_finish(void);

#endif
