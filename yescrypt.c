
#include "cpuminer-config.h"
#include "miner.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "yescrypt.h"
#include "yescryptcommon.c"
#include "yescrypt-simd.c"
#include "sha256_Y.c"

int scanhash_yescrypt(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce, unsigned long *hashes_done)
{
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];

	uint32_t hash64[8] __attribute__((aligned(32)));
	uint32_t endiandata[32];
	char data_str[161], hash_str[65], target_str[65];
	//we need bigendian data...
	int kk=0;
	for (; kk < 32; kk++)
	{
		be32enc(&endiandata[kk], ((uint32_t*)pdata)[kk]);
	};

	do {
		pdata[19] = ++n;
		be32enc(&endiandata[19], n); 
		yescrypt_hash_sp((unsigned char*) &endiandata, (unsigned char*) hash64);
		if ((hash64[7] < ptarget[7]) || ((hash64[7] == ptarget[7]) && (hash64[6] < ptarget[6])) &&
				fulltest(hash64, ptarget)) {
			*hashes_done = n - first_nonce + 1;
            if (opt_debug) {
                bin2hex(hash_str, (unsigned char *)hash64, 32);
                bin2hex(target_str, (unsigned char *)ptarget, 32);
                bin2hex(data_str, (unsigned char *)endiandata, 80);
                applog(LOG_DEBUG, "DEBUG: [%d thread] Found share!\ndata   %s\nhash   %s\ntarget %s", thr_id, 
                    data_str,
                    hash_str,
                    target_str);
            }
			return true;
		}
	} while (n < max_nonce && !work_restart[thr_id].restart);	
	
	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}
