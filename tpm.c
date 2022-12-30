/**
 * @file tpm.c
 * @author liuqi (liuqi1@kylinos.cn)
 * @brief 
 * @version 0.1
 * @date 2023-11-14
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#include "ldim.h"

#include <linux/tpm.h>
#include <linux/version.h>

static int pcr = 0; // off by default
static int tcm = 0; // tpm by default, others use tcm
static int pcr_alg = 0; // tpm pcr extend algorithm (#define HASH_ALGO_SM3 0)

module_param(pcr, int, S_IRUSR | S_IWUSR);
module_param(tcm, int, S_IRUSR | S_IWUSR);
module_param(pcr_alg, int, S_IRUSR | S_IWUSR);

#if LINUX_VERSION_CODE > KERNEL_VERSION(5, 1, 0)
struct ldim_tpm {
	struct tpm_chip *chip;
	struct tpm_digest *digests;
	int bank;
};

static int _tpm_init(struct ldim_tpm *tpm, int algo)
{
	int ret = 0;
	int i = 0;

	tpm->chip = tpm_default_chip();
	if (tpm->chip == NULL)
		return -ENODEV;

	tpm->digests = kcalloc(tpm->chip->nr_allocated_banks,
			       sizeof(struct tpm_digest), GFP_KERNEL);
	if (tpm->digests == NULL) {
		ret = -ENOMEM;
		goto err;
	}

	tpm->bank = -1;
	for (i = 0; i < tpm->chip->nr_allocated_banks; i++) {
		tpm->digests[i].alg_id = tpm->chip->allocated_banks[i].alg_id;
		if (tpm->chip->allocated_banks[i].crypto_id == algo)
			tpm->bank = i;

		memset(tpm->digests[i].digest, 0xff, TPM_MAX_DIGEST_SIZE);
	}

	if (tpm->bank == -1) {
		ret = -ENOENT; /* fail to find matched TPM bank */
		goto err;
	}

	return 0;
err:
	put_device(&tpm->chip->dev);
	if (tpm->digests != NULL) {
		kfree(tpm->digests);
		tpm->digests = NULL;
	}

	tpm->chip = NULL;
	return ret;
}

static int _tpm_extend(const u8 *hash)
{
    int err;
    static struct ldim_tpm *tpm = NULL;
    if (tpm == NULL) {
        tpm = (typeof(struct ldim_tpm *))kmalloc(sizeof(struct ldim_tpm), GFP_KERNEL);
        err = _tpm_init(tpm, pcr_alg);
        if(err){
            pr_warn("tpm init err:%d\n", err);
            return err;
        }
    }

	memcpy(tpm->digests[tpm->bank].digest, hash, SHA256_DIGEST_SIZE);
	return tpm_pcr_extend(tpm->chip, pcr, tpm->digests);
}

#else

static int _tpm_extend(const u8 *hash)
{
    static int (*ldim_pcr_extend)(void *, int , const u8 *) = NULL;
    static void *default_pcr_chip = NULL;

    if (ldim_pcr_extend == NULL){
        if(tcm){ // tcm
            request_module("tcm_tis_lpc");
            default_pcr_chip = (void *)0xffff;
            ldim_pcr_extend = (typeof(ldim_pcr_extend))ksyms_kallsyms_lookup_name("lpc_tcm_pcr_extend");
            if(!ldim_pcr_extend){
                pr_warn("not found symbol: lpc_tcm_pcr_extend\n");
                return -EINVAL;
            }
        }else{ // use tpm
            ldim_pcr_extend = (typeof(ldim_pcr_extend))tpm_pcr_extend;
        }
    }

    return ldim_pcr_extend(default_pcr_chip, pcr, hash);
}

#endif


void ldim_tpm_extend(const u8 *hash, const char *path)
{
    int err;
    char *hash_hex;

    if(pcr == 0)
        return;

    err = _tpm_extend(hash);
    if(err){
        pr_warn("ldim pcr extend err(%d)\n", err);
        return ;
    }
  
    // log
    hash_hex = kzalloc(PAGE_SIZE, GFP_KERNEL);

    bin2hex(hash_hex, hash, HASH_ALG_SIZE);

    audit_log(audit_context(), GFP_ATOMIC, AUDIT_KYRG,
        "pcr=%d measurement=%s path=%s\n",
        pcr, hash_hex, path);

    kfree(hash_hex);
}
