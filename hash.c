/**
 * @file hash.c
 * @author liuqi (liuqi1@kylinos.cn)
 * @brief
 * @version 0.1
 * @date 2022-12-17
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "ldim.h"

#include <linux/kernel.h>
#include <crypto/hash.h>
#include <linux/mutex.h>

static DEFINE_MUTEX(calc_hash_mutex);

static struct shash_desc *desc = NULL;

int hash_value_init(void)
{
    mutex_lock(&calc_hash_mutex);
    return crypto_shash_init(desc);
}

int hash_value_update(const u8 *data, unsigned int len)
{
    return crypto_shash_update(desc, data, len);
}

int hash_value_final(u8 *out)
{
    int err;
    err = crypto_shash_final(desc, out);
    mutex_unlock(&calc_hash_mutex);
    return err;
}

int hash_value(const u8 *data, unsigned int len, u8 *out)
{
    int err;
    mutex_lock(&calc_hash_mutex);
    err = crypto_shash_digest(desc, data, len, out);
    mutex_unlock(&calc_hash_mutex);
    return err;
}

int hash_alg_init(char *hash_alg_name)
{
    struct crypto_shash *alg;

    alg = crypto_alloc_shash(hash_alg_name, 0, 0);
    if (IS_ERR_OR_NULL(alg))
        return PTR_ERR(alg) ?: -1;

    desc = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(alg), GFP_KERNEL);
    if (IS_ERR_OR_NULL(desc)){
        crypto_free_shash(desc->tfm);
        return PTR_ERR(desc) ?: -1;
    }

    desc->tfm = alg;
    pr_debug("Successfully init hash alg: %s\n", hash_alg_name);
    return 0;
}

void hash_alg_exit(void)
{
    if(!desc)
        return ;

    crypto_free_shash(desc->tfm);
    kfree(desc);
    pr_debug("Successfully exit hash alg\n");
}

// 256 bits = 32 bytes
void example_hash_256(void)
{
#define BUF_SIZE 32
    hash_alg_init("sha256");

    {
        const u8 *data = "abc";
        unsigned int len = strlen(data);
        u8 *out = kzalloc(BUF_SIZE, GFP_KERNEL);

        hash_value_init();
        hash_value_update(data, len);
        hash_value_final(out);

        print_hex_dump(KERN_DEBUG, "", DUMP_PREFIX_NONE, 16, 1, out, BUF_SIZE, false);
        kfree(out);
    }

    hash_alg_exit();
}