#include <openssl/evp.h>
#include <stdio.h>

int main(void)
{
    unsigned char key[32] = "qwertyuiopasdfghqwertyuiopasdfgh";
    unsigned char iv[16] = "qwertyuiopasdfgh";

    EVP_CIPHER_CTX * ctx;
    unsigned char enc_buf[128];
    unsigned char dec_buf[128];
    int total_enc_len, enc_len;
    int total_dec_len, dec_len;

    int msg_len[] = {1, 16, 17, 32, 33};
    unsigned char * msg[] = {
        (unsigned char *)"1",
        (unsigned char *)"1234567890123456",
        (unsigned char *)"12345678901234567",
        (unsigned char *)"12345678901234567890123456789012",
        (unsigned char *)"123456789012345678901234567890123"
    };

    for (int i = 0; i < sizeof(msg_len) / sizeof(int); ++i) {
        ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
        EVP_EncryptUpdate(ctx, enc_buf, &enc_len, msg[i], msg_len[i]);
        total_enc_len = enc_len;
        printf("enc upd len: %d\n", enc_len);
        EVP_EncryptFinal_ex(ctx, enc_buf + total_enc_len, &enc_len);
        total_enc_len += enc_len;
        printf("enc fnl len: %d\n", enc_len);
        EVP_CIPHER_CTX_free(ctx);

        printf("enc msg: 0x");
        for (int j = 0; j < total_enc_len; ++j)
            printf("%02x", enc_buf[j]);
        printf("\n");

        ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
        EVP_DecryptUpdate(ctx, dec_buf, &dec_len, enc_buf, total_enc_len);
        total_dec_len = dec_len;
        printf("dec upd len: %d\n", dec_len);
        EVP_DecryptFinal_ex(ctx, dec_buf + total_dec_len, &dec_len);
        total_dec_len += dec_len;
        printf("dec fnl len: %d\n", dec_len);
        EVP_CIPHER_CTX_free(ctx);

        printf("ori msg: %s\n", msg[i]);
        dec_buf[total_dec_len] = '\0';
        printf("dec msg: %s\n", dec_buf);

        printf("\n");
    }

    return 0;
}