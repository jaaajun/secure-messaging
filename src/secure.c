#include "protocol.h"
#include "secure.h"
#include <openssl/rand.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdlib.h>

static char * dh_parameter_p;
static int dh_parameter_g = DH_GENERATOR_2;

static ssize_t _sendall(int channel, const void * buf, size_t len, int flags)
{
    ssize_t total_send_len, ret;

    total_send_len = 0;
    while (total_send_len < len)
    {
        ret = send(channel, buf + total_send_len, len - total_send_len, flags);
        if (ret >= 0)
            total_send_len += ret;
        else if (errno != EINTR)
            return -1;
    }

    return total_send_len;
}

static ssize_t _recvall(int channel, void * buf, size_t len, int flags)
{
    ssize_t total_recv_len, ret;

    total_recv_len = 0;
    while (total_recv_len < len)
    {
        ret = recv(channel, buf + total_recv_len, len - total_recv_len, flags);
        if (ret > 0)
            total_recv_len += ret;
        else if (ret == 0)
            return 0;
        else if (errno != EINTR)
            return -1;
    }

    return total_recv_len;
}

ssize_t secure_send(int channel, const void * buf, size_t len, int flags,
                    const unsigned char * key, const unsigned char * iv)
{
    EVP_CIPHER_CTX * ctx;
    unsigned char * enc_buf;
    int total_enc_len, enc_len;
    ssize_t send_len;

    enc_buf = (unsigned char *)malloc(len - len % 16 + 16);

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, enc_buf, &enc_len, buf, len);
    total_enc_len = enc_len;
    EVP_EncryptFinal_ex(ctx, enc_buf + total_enc_len, &enc_len);
    total_enc_len += enc_len;
    EVP_CIPHER_CTX_free(ctx);

    send_len = _sendall(channel, enc_buf, total_enc_len, flags);

    free(enc_buf);

    return send_len;
}

ssize_t secure_recv(int channel, void * buf, size_t len, int flags,
                    const unsigned char * key, const unsigned char * iv)
{
    EVP_CIPHER_CTX * ctx;
    unsigned char * recv_buf;
    int align_len, total_dec_len, dec_len;
    ssize_t recv_len;

    align_len = len - len % 16 + 16;
    recv_buf = (unsigned char *)malloc(align_len);

    recv_len = _recvall(channel, recv_buf, align_len, flags);
    if (recv_len > 0) {
        ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
        EVP_DecryptUpdate(ctx, buf, &dec_len, recv_buf, recv_len);
        total_dec_len = dec_len;
        EVP_DecryptFinal_ex(ctx, buf + total_dec_len, &dec_len);
        total_dec_len += dec_len;
        EVP_CIPHER_CTX_free(ctx);
    }

    free(recv_buf);

    return recv_len;
}

int secure_server_init(void)
{
    DH * dh;

    RAND_poll();
    dh = DH_new();
    DH_generate_parameters_ex(dh, 2048, dh_parameter_g, NULL);
    dh_parameter_p = BN_bn2hex(DH_get0_p(dh));
    DH_free(dh);

    return 0;
}

int secure_server_buildkey(int channel, unsigned char * key, unsigned char * iv)
{
    DH * dh;
    BIGNUM * p = NULL;
    BIGNUM * g = NULL;
    char * pub_key;
    BIGNUM * peer_pub_key = NULL;
    unsigned char * shared_key;
    char buf[1024];

    buf[0] = PROTOCOL_BUILD_P;
    memcpy(&(buf[1]), dh_parameter_p, 512);
    _sendall(channel, buf, 513, 0);

    dh = DH_new();
    BN_hex2bn(&p, dh_parameter_p);
    g = BN_new();
    BN_set_word(g, dh_parameter_g);
    DH_set0_pqg(dh, p, NULL, g);
    DH_generate_key(dh);

    pub_key = BN_bn2hex(DH_get0_pub_key(dh));
    buf[0] = PROTOCOL_BUILD_PUBK;
    memcpy(&(buf[1]), pub_key, 512);
    _sendall(channel, buf, 513, 0);

    _recvall(channel, buf, 513, 0);
    buf[513] = '\0';
    BN_hex2bn(&peer_pub_key, &(buf[1]));

    /* shared_key is 256 bytes */
    shared_key = (unsigned char *)OPENSSL_malloc(DH_size(dh));
    DH_compute_key(shared_key, peer_pub_key, dh);

    memcpy(key, shared_key, 32);
    memcpy(iv, shared_key + 32, 16);

    OPENSSL_free(shared_key);
    BN_free(peer_pub_key);
    OPENSSL_free(pub_key);
    DH_free(dh);

    return 0;
}

void secure_server_finish(void)
{
    OPENSSL_free(dh_parameter_p);
}

int secure_client_init(void)
{
    return 0;
}

int secure_client_buildkey(int channel, unsigned char * key, unsigned char * iv)
{
    DH * dh;
    BIGNUM * p = NULL;
    BIGNUM * g = NULL;
    BIGNUM * peer_pub_key = NULL;
    char * pub_key;
    unsigned char * shared_key;
    char buf[1024];

    _recvall(channel, buf, 513, 0);
    buf[513] = '\0';
    BN_hex2bn(&p, &(buf[1]));

    dh = DH_new();
    g = BN_new();
    BN_set_word(g, dh_parameter_g);
    DH_set0_pqg(dh, p, NULL, g);
    DH_generate_key(dh);

    _recvall(channel, buf, 513, 0);
    buf[513] = '\0';
    BN_hex2bn(&peer_pub_key, &(buf[1]));

    pub_key = BN_bn2hex(DH_get0_pub_key(dh));
    buf[0] = PROTOCOL_BUILD_PUBK;
    memcpy(&(buf[1]), pub_key, 512);
    _sendall(channel, buf, 513, 0);

    /* shared_key is 256 bytes */
    shared_key = (unsigned char *)OPENSSL_malloc(DH_size(dh));
    DH_compute_key(shared_key, peer_pub_key, dh);

    memcpy(key, shared_key, 32);
    memcpy(iv, shared_key + 32, 16);

    OPENSSL_free(shared_key);
    OPENSSL_free(pub_key);
    BN_free(peer_pub_key);
    DH_free(dh);

    return 0;
}

void secure_client_finish(void)
{
    ;
}
