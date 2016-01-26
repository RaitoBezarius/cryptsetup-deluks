/*
 * LUKS - Linux Unified Key Setup v2, LUKS2 type keyslot handler
 *
 * Copyright (C) 2015-2016, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2015-2016, Milan Broz. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "luks2_internal.h"

/* FIXME: move keyslot encryption to crypto backend */
#include "../luks1/af.h"

#define LUKS_SALTSIZE 32
#define LUKS_SLOT_ITERATIONS_MIN 1000
#define LUKS_STRIPES 4000

static int luks2_keyslot_set_key(struct crypt_device *cd,
	json_object *jobj_keyslot, json_object *jobj_area,
	const char *password, size_t passwordLen,
	const char *volume_key, size_t volume_key_len)
{
	struct volume_key *derived_key;
	char salt[LUKS_SALTSIZE], cipher[MAX_CIPHER_LEN], cipher_mode[MAX_CIPHER_LEN];
	char *AfKey = NULL, *salt_base64 = NULL;
	size_t AFEKSize;
	json_object *jobj2;
	uint32_t iterations, memory, parallel, sector_offset;
	const struct crypt_pbkdf_type *pbkdf;
	int r;

	/*
	 * Get attributes from JSON keyslot metadata
	 */
	if (!json_object_object_get_ex(jobj_area, "offset", &jobj2))
		return -EINVAL;
	/* FIXME: wrong for any value > INT32_MAX */
	sector_offset = json_object_get_int(jobj2) / SECTOR_SIZE;

	if (!json_object_object_get_ex(jobj_keyslot, "enc_alg", &jobj2))
		return -EINVAL;
	r = crypt_parse_name_and_mode(json_object_get_string(jobj2), cipher, NULL, cipher_mode);
	if (r < 0)
		return r;

	pbkdf = crypt_get_pbkdf_type(cd);
	if (!pbkdf || !pbkdf->type || !pbkdf->hash) {
		log_dbg("Default PBKDF was not set.");
		return -EINVAL;
	}

	if (!strcmp(pbkdf->type, "pbkdf2")) {
		uint32_t PBKDF2_per_sec = 0;
		double PBKDF2_temp;
		/*
		 * Benchmark KDF and calculate slot iterations
		 */
		r = crypt_benchmark_pbkdf(cd, pbkdf, "foo", 3, "bar", 3, volume_key_len, &PBKDF2_per_sec);
		if (r < 0) {
			log_err(cd, _("Not compatible PBKDF2 options (using hash algorithm %s).\n"), pbkdf->hash);
			return r;
		}

		PBKDF2_temp = (double)PBKDF2_per_sec * pbkdf->time_ms / 1000.;
		if (PBKDF2_temp > UINT32_MAX)
			return -EINVAL;
		iterations = at_least((uint32_t)PBKDF2_temp, LUKS_SLOT_ITERATIONS_MIN);
		memory = 0;
		parallel = 0;
		log_dbg("Using hash %s for PBKDF2, %d iterations.", pbkdf->hash, iterations);
	} else if (!strcmp(pbkdf->type, "argon2")) {
		memory = pbkdf->memory_kb;
		parallel = pbkdf->parallel_threads;

		r = crypt_benchmark_pbkdf(cd, pbkdf, "foo", 3, "0123456789abcdef", 16,
					volume_key_len, &iterations);
		if (r < 0) {
			log_err(cd, _("Not compatible Argon2 options.\n"));
			return r;
		}
		log_dbg("Using Argon2, %d time cost, %d memory cost, %d parallel cost.",
			iterations, memory, parallel);
	} else
		return -EINVAL;

	json_object_object_add(jobj_keyslot, "iterations", json_object_new_int(iterations));
	json_object_object_add(jobj_keyslot, "memory", json_object_new_int(memory));
	json_object_object_add(jobj_keyslot, "parallel", json_object_new_int(parallel));
	json_object_object_add(jobj_keyslot, "kdf_alg", json_object_new_string(pbkdf->type));
	json_object_object_add(jobj_keyslot, "hash_alg", json_object_new_string(pbkdf->hash));

	/*
	 * Get salt and allocate derived key storage.
	 */
	r = crypt_random_get(cd, salt, LUKS_SALTSIZE, CRYPT_RND_SALT);
	if (r < 0)
		return r;
	base64_encode_alloc(salt, LUKS_SALTSIZE, &salt_base64);
	if (!salt_base64)
		return -ENOMEM;
	json_object_object_add(jobj_keyslot, "salt", json_object_new_string(salt_base64));
	free(salt_base64);

	derived_key = crypt_alloc_volume_key(volume_key_len, NULL);
	if (!derived_key)
		return -ENOMEM;
	/*
	 * Calculate keyslot content, split and store it to keyslot area.
	 */
	r = crypt_pbkdf(pbkdf->type, pbkdf->hash, password, passwordLen,
			salt, LUKS_SALTSIZE,
			derived_key->key, volume_key_len,
			iterations, memory, parallel);
	if (r < 0) {
		crypt_free_volume_key(derived_key);
		return r;
	}

	AFEKSize = AF_split_sectors(volume_key_len, LUKS_STRIPES) * SECTOR_SIZE;
	AfKey = crypt_safe_alloc(AFEKSize);
	if (!AfKey) {
		crypt_free_volume_key(derived_key);
		return -ENOMEM;
	}

	r = AF_split(volume_key, AfKey, volume_key_len, LUKS_STRIPES, pbkdf->hash);

	if (r == 0) {
		log_dbg("Updating keyslot area [0x%04x].", sector_offset * SECTOR_SIZE);
		/* FIXME: sector_offset should be size_t, fix LUKS_encrypt... accordingly */
		r = LUKS_encrypt_to_storage(AfKey, AFEKSize, cipher, cipher_mode,
				    derived_key, sector_offset, cd);
	}

	crypt_safe_free(AfKey);
	crypt_free_volume_key(derived_key);
	if (r < 0)
		return r;

	json_object_object_add(jobj_keyslot, "state", json_object_new_string("active"));

	return 0;
}

static int luks2_keyslot_get_key(struct crypt_device *cd,
	json_object *jobj_keyslot, json_object *jobj_area,
	const char *password, size_t passwordLen,
	char *volume_key, size_t volume_key_len)
{
	struct volume_key *derived_key;
	char *AfKey;
	size_t AFEKSize;
	const char *hash, *kdf;
	char salt[LUKS_SALTSIZE], cipher[MAX_CIPHER_LEN], cipher_mode[MAX_CIPHER_LEN];
	json_object *jobj2;
	uint32_t iterations, memory, parallel, sector_offset;
	size_t salt_len;
	int r;

	/*
	 * Get attributes from JSON keyslot metadata
	 */
	if (!json_object_object_get_ex(jobj_keyslot, "hash_alg", &jobj2))
		return -EINVAL;
	hash = json_object_get_string(jobj2);

	if (!json_object_object_get_ex(jobj_keyslot, "kdf_alg", &jobj2))
		return -EINVAL;
	kdf = json_object_get_string(jobj2);

	if (!json_object_object_get_ex(jobj_area, "offset", &jobj2))
		return -EINVAL;
	/* FIXME: wrong for any value > INT32_MAX */
	sector_offset = json_object_get_int(jobj2) / SECTOR_SIZE;

	if (!json_object_object_get_ex(jobj_keyslot, "enc_alg", &jobj2))
		return -EINVAL;
	r = crypt_parse_name_and_mode(json_object_get_string(jobj2), cipher, NULL, cipher_mode);
	if (r < 0)
		return r;

	if (!json_object_object_get_ex(jobj_keyslot, "iterations", &jobj2))
		return -EINVAL;
	iterations = json_object_get_int(jobj2);

	if (!json_object_object_get_ex(jobj_keyslot, "memory", &jobj2))
		return -EINVAL;
	memory = json_object_get_int(jobj2);

	if (!json_object_object_get_ex(jobj_keyslot, "parallel", &jobj2))
		return -EINVAL;
	parallel = json_object_get_int(jobj2);

	if (!json_object_object_get_ex(jobj_keyslot, "salt", &jobj2))
		return -EINVAL;
	salt_len = LUKS_SALTSIZE;
	base64_decode(json_object_get_string(jobj2),
		      json_object_get_string_len(jobj2),
		      salt, &salt_len);
	if (salt_len != LUKS_SALTSIZE)
		return -EINVAL;
	/*
	 * Allocate derived key storage space.
	 */
	derived_key = crypt_alloc_volume_key(volume_key_len, NULL);
	if (!derived_key)
		return -ENOMEM;

	AFEKSize = AF_split_sectors(volume_key_len, LUKS_STRIPES) * SECTOR_SIZE;
	AfKey = crypt_safe_alloc(AFEKSize);
	if (!AfKey) {
		crypt_free_volume_key(derived_key);
		return -ENOMEM;
	}
	/*
	 * Calculate derived key, decrypt keyslot content and merge it.
	 */
	r = crypt_pbkdf(kdf, hash, password, passwordLen,
			salt, LUKS_SALTSIZE,
			derived_key->key, volume_key_len,
			iterations, memory, parallel);

	if (r == 0) {
		log_dbg("Reading keyslot area [0x%04x].", sector_offset * SECTOR_SIZE);
		/* FIXME: sector_offset should be size_t, fix LUKS_decrypt... accordingly */
		r = LUKS_decrypt_from_storage(AfKey, AFEKSize, cipher, cipher_mode,
				      derived_key, sector_offset, cd);
	}

	if (r == 0)
		r = AF_merge(AfKey, volume_key, volume_key_len, LUKS_STRIPES, hash);

	crypt_free_volume_key(derived_key);
	crypt_safe_free(AfKey);

	return r;
}

static int luks2_keyslot_open(struct crypt_device *cd,
	int keyslot,
	const char *password,
	size_t password_len,
	char *volume_key,
	size_t volume_key_len)
{
	struct luks2_hdr *hdr;
	json_object *jobj_keyslot, *jobj_area;

	log_dbg("Trying to open LUKS2 keyslot %d.", keyslot);

	if (!(hdr = crypt_get_hdr(cd, CRYPT_LUKS2)))
		return -EINVAL;

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, keyslot);
	jobj_area    = LUKS2_get_area_jobj(hdr, keyslot);
	if (!jobj_keyslot || !jobj_area)
		return -EINVAL;

	return luks2_keyslot_get_key(cd, jobj_keyslot, jobj_area,
				     password, password_len,
				     volume_key, volume_key_len);
}

static int luks2_keyslot_store(struct crypt_device *cd,
	int keyslot,
	const char *password,
	size_t password_len,
	const char *volume_key,
	size_t volume_key_len)
{
	struct luks2_hdr *hdr;
	json_object *jobj_keyslot, *jobj_area;
	int r;

	log_dbg("Calculating attributes for LUKS2 keyslot %d.", keyslot);

	if (!(hdr = crypt_get_hdr(cd, CRYPT_LUKS2)))
		return -EINVAL;

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, keyslot);
	jobj_area    = LUKS2_get_area_jobj(hdr, keyslot);
	if (!jobj_keyslot || !jobj_area)
		return -EINVAL;

	r = luks2_keyslot_set_key(cd, jobj_keyslot, jobj_area,
				  password, password_len,
				  volume_key, volume_key_len);
	if (r < 0)
		return r;

	r = LUKS2_hdr_write(cd, hdr);
	if (r < 0)
		return r;

	return keyslot;
}

static int luks2_keyslot_wipe(struct crypt_device *cd, int keyslot)
{
	json_object *jobj_keyslot;

	jobj_keyslot = LUKS2_get_keyslot_jobj(crypt_get_hdr(cd, CRYPT_LUKS2), keyslot);
	if (!jobj_keyslot)
		return -EINVAL;

	json_object_object_add(jobj_keyslot, "salt", json_object_new_string(""));
	json_object_object_add(jobj_keyslot, "iterations", json_object_new_int64(0));

	return 0;
}

static int luks2_keyslot_dump(struct crypt_device *cd, int keyslot)
{
	json_object *jobj_keyslot, *jobj1;

	jobj_keyslot = LUKS2_get_keyslot_jobj(crypt_get_hdr(cd, CRYPT_LUKS2), keyslot);
	if (!jobj_keyslot)
		return -EINVAL;

	json_object_object_get_ex(jobj_keyslot, "enc_alg", &jobj1);
	log_std(cd, "\tCipher:     %s\n", json_object_get_string(jobj1));

	json_object_object_get_ex(jobj_keyslot, "kdf_alg", &jobj1);
	log_std(cd, "\tPBKDF:      %s\n", json_object_get_string(jobj1));

	json_object_object_get_ex(jobj_keyslot, "hash_alg", &jobj1);
	log_std(cd, "\tHash:       %s\n", json_object_get_string(jobj1));

	json_object_object_get_ex(jobj_keyslot, "stripes", &jobj1);
	log_std(cd, "\tStripes:    %u\n", json_object_get_int(jobj1));

	json_object_object_get_ex(jobj_keyslot, "state", &jobj1);
	if (!strcmp("active", json_object_get_string(jobj1))) {
		json_object_object_get_ex(jobj_keyslot, "iterations", &jobj1);
		log_std(cd, "\tIterations: %" PRIu64 "\n", json_object_get_int64(jobj1));

		json_object_object_get_ex(jobj_keyslot, "memory", &jobj1);
		log_std(cd, "\tMemory:  %" PRIu64 "\n", json_object_get_int64(jobj1));

		json_object_object_get_ex(jobj_keyslot, "parallel", &jobj1);
		log_std(cd, "\tThreads: %" PRIu64 "\n", json_object_get_int64(jobj1));

		json_object_object_get_ex(jobj_keyslot, "salt", &jobj1);
		log_std(cd, "\tSalt:       ");
		hexprint_base64(cd, jobj1, " ", "            ");
	}

	return 0;
}

static int contains(json_object *jobj, const char *key, json_type type)
{
	json_object *sobj;

	if (!json_object_object_get_ex(jobj, key, &sobj) ||
	    !json_object_is_type(sobj, type))
		return 0;

	return 1;
}

static int luks2_keyslot_validate(struct crypt_device *cd, int keyslot)
{
	json_object *jobj_keyslot;

	jobj_keyslot = LUKS2_get_keyslot_jobj(crypt_get_hdr(cd, CRYPT_LUKS2), keyslot);
	if (!jobj_keyslot)
		return -EINVAL;

	if (!contains(jobj_keyslot, "salt", json_type_string) ||
	    !contains(jobj_keyslot, "stripes", json_type_int) ||
	    !contains(jobj_keyslot, "iterations", json_type_int) ||
	    !contains(jobj_keyslot, "memory", json_type_int) ||
	    !contains(jobj_keyslot, "parallel", json_type_int) ||
	    !contains(jobj_keyslot, "kdf_alg", json_type_string) ||
	    !contains(jobj_keyslot, "enc_alg", json_type_string) ||
	    !contains(jobj_keyslot, "hash_alg", json_type_string))
		return -EINVAL;

	return 0;
}

const keyslot_handler luks2_keyslot = {
	.name  = "luks2",
	.open  = luks2_keyslot_open,
	.store = luks2_keyslot_store,
	.wipe  = luks2_keyslot_wipe,
	.dump  = luks2_keyslot_dump,
	.validate = luks2_keyslot_validate,
};
