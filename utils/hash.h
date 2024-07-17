//#ifdef _HASH_H_
//#define _HASH_H_

int hash_password(const char *plaintext, const unsigned char *salt, unsigned char *output);
int constant_time_compare(const unsigned char *a, const unsigned char *b, size_t length);
int compare_hash(const char *password, unsigned char *salt, unsigned char *hash_passwd);

//#endif