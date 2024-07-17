#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <crypto/hash.h>
#include <linux/module.h>
#include <linux/random.h> 

#define SHA256_LENGTH 32
#define SALT_LENGTH 16

MODULE_AUTHOR("Luca Di Marco");
MODULE_DESCRIPTION("Aux function for the reference monitor");
MODULE_LICENSE("GPL");

int hash_password(const char *plaintext, unsigned char *salt, unsigned char *output) {
    struct crypto_shash *sha256;
    struct shash_desc *shash;
    int size, ret;
    char salted_input[256];
    unsigned char salt_constant[SALT_LENGTH] = "salt";

    if (!plaintext || !salt || !output) {
        printk(KERN_ERR "Invalid input to hash_password\n");
        return -EINVAL;
    }

    get_random_bytes(salt, SALT_LENGTH);
    
    // Combina il salt con la password
    snprintf(salted_input, sizeof(salted_input), "%s%s", salt_constant, plaintext);

    sha256 = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(sha256)) {
        return PTR_ERR(sha256);
    }

    size = sizeof(struct shash_desc) + crypto_shash_descsize(sha256);
    shash = kmalloc(size, GFP_KERNEL);
    if (!shash) {
        printk(KERN_ERR "Failed to allocate shash descriptor\n");
        crypto_free_shash(sha256);
        return -ENOMEM;
    }

    shash->tfm = sha256;

    ret = crypto_shash_digest(shash, salted_input, strlen(salted_input), output);
    if (ret) {
        printk(KERN_ERR "crypto_shash_digest failed: %d\n", ret);
    }

    kfree(shash);
    crypto_free_shash(sha256);

    return ret;
}

int constant_time_compare(const unsigned char *a, const unsigned char *b, size_t length) {
    unsigned int result = 0;
    size_t i;

    for (i = 0; i < length; i++) {
        result |= a[i] ^ b[i];
    }

    return result;
}

int compare_hash(const char *password, unsigned char *salt, unsigned char *hash_passwd) {
    unsigned char hash[SHA256_LENGTH];

    if (hash_password(password, salt, hash) == 0) {
        if (constant_time_compare(hash, hash_passwd, SHA256_LENGTH) == 0) {
            //printk(KERN_INFO "Password correct\n");
            return 0;
        } else {
            //printk(KERN_INFO "Password incorrect\n");
            return -1;
        }
    } else {
        printk(KERN_ERR "Error hashing password\n");
        return -1;
    }
}

