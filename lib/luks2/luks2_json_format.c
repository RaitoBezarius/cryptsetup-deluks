/*
 * LUKS - Linux Unified Key Setup v2, LUKS2 header format code
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
#include <uuid/uuid.h>

struct area {
	uint64_t offset;
	uint64_t length;
};

static struct area areas_256[8] = {
{  32768, 131072 },
{ 163840, 131072 },
{ 294912, 131072 },
{ 425984, 131072 },
{ 557056, 131072 },
{ 688128, 131072 },
{ 819200, 131072 },
{ 950272, 131072 }};

static struct area areas_512[8] = {
{   32768, 258048 },
{  290816, 258048 },
{  548864, 258048 },
{  806912, 258048 },
{ 1064960, 258048 },
{ 1323008, 258048 },
{ 1581056, 258048 },
{ 1839104, 258048 }};

static const char *uint64_to_str(char *buffer, size_t size, uint64_t *val)
{
	int r = snprintf(buffer, size, "%" PRIu64, *val);
	if (r < 0) {
		log_dbg("Failed to convert integer to string.");
		*buffer = '\0';
	} else if ((size_t)r >= size) {
		log_dbg("Not enough space to store '%" PRIu64 "' to a string buffer.", *val);
		*buffer = '\0';
	}

	return buffer;
}

int LUKS2_keyslot_luks2_format(struct crypt_device *cd, struct luks2_hdr *hdr,
			       int keyslot, const char *cipher, size_t keylength)
{
	const struct crypt_pbkdf_type *pbkdf;
	char json_buf[4096];

	pbkdf = crypt_get_pbkdf_type(cd);

	snprintf(json_buf, sizeof(json_buf),
		 "{\"type\":\"%s\",\"state\":\"inactive\",\"key_length\":%zu,"
		 "\"salt\":\"\",\"kdf_alg\":\"%s\",\"iterations\":%u,"
		 "\"memory\":%u,\"parallel\":%u,\"stripes\":4000,\"enc_alg\":\"%s\",\"hash_alg\":\"%s\"}",
		 "luks2", keylength, pbkdf->type, pbkdf->time_ms,
		 pbkdf->memory_kb, pbkdf->parallel_threads, cipher, pbkdf->hash);

	return LUKS2_keyslot_create(cd, hdr, keyslot, "luks2", json_buf, 0);
}

int LUKS2_generate_hdr(
	struct crypt_device *cd,
	struct luks2_hdr *hdr,
	const struct volume_key *vk,
	const char *cipherName,
	const char *cipherMode,
	const char *uuid,
	unsigned int alignPayload,
	unsigned int alignOffset,
	int detached_metadata_device)
{
	struct json_object *jobj1, *jobj2, *jobj_keyslots, *jobj_areas, *jobj_segments;
	const digest_handler *digest_handler;
	int i;
	char bignum[24], num[16], cipher[128];
	uint64_t offset;
	uuid_t partitionUuid;
	struct area *areas;

	if (vk->keylength <= 32)
		areas = &areas_256[0];
	else if (vk->keylength <= 64)
		areas = &areas_512[0];
	else
		return -EINVAL;

	digest_handler = LUKS2_digest_handler_type(cd, "luks1");
	if (!digest_handler)
		return -EINVAL;

	hdr->hdr_size = LUKS2_HDR_16K_LEN;
	hdr->seqid = 1;
	hdr->version = 2;
	memset(hdr->label, 0, LUKS2_LABEL_L);
	strcpy(hdr->checksum_alg, "sha256");
	crypt_random_get(NULL, (char*)hdr->salt1, LUKS2_SALT_L, CRYPT_RND_SALT);
	crypt_random_get(NULL, (char*)hdr->salt2, LUKS2_SALT_L, CRYPT_RND_SALT);

	if (uuid && uuid_parse(uuid, partitionUuid) == -1) {
		log_err(cd, _("Wrong LUKS UUID format provided.\n"));
		return -EINVAL;
	}
	if (!uuid)
		uuid_generate(partitionUuid);

	uuid_unparse(partitionUuid, hdr->uuid);

	if (*cipherMode != '\0')
		snprintf(cipher, sizeof(cipher), "%s-%s", cipherName, cipherMode);
	else
		snprintf(cipher, sizeof(cipher), "%s", cipherName);

	hdr->jobj = json_object_new_object();

	jobj_keyslots = json_object_new_object();
	json_object_object_add(hdr->jobj, "keyslots", jobj_keyslots);
	jobj_segments = json_object_new_object();
	json_object_object_add(hdr->jobj, "segments", jobj_segments);
	jobj_areas = json_object_new_object();
	json_object_object_add(hdr->jobj, "areas", jobj_areas);
	json_object_object_add(hdr->jobj, "digests", json_object_new_object());
	json_object_object_add(hdr->jobj, "config", json_object_new_object());

	digest_handler->store(cd, 0, vk->key, vk->keylength);

	jobj1 = json_object_new_object();
	json_object_object_add(jobj1, "type", json_object_new_string("crypt"));
	json_object_object_add(jobj1, "keyslots", json_object_new_array());
	if (detached_metadata_device)
		offset = alignPayload * SECTOR_SIZE;
	else
		offset = size_round_up(areas[7].offset + areas[7].length, alignPayload * SECTOR_SIZE);
	json_object_object_add(jobj1, "offset", json_object_new_string(uint64_to_str(bignum, sizeof(bignum), &offset)));
	json_object_object_add(jobj1, "iv_offset", json_object_new_string("0"));
	json_object_object_add(jobj1, "length", json_object_new_string("dynamic"));
	json_object_object_add(jobj1, "cipher", json_object_new_string(cipher));
	json_object_object_add(jobj1, "block", json_object_new_int(SECTOR_SIZE));
	json_object_object_add(jobj_segments, "0", jobj1);

	for (i = 0; i < LUKS2_KEYSLOTS_WITH_AREAS; i++) {
		LUKS2_keyslot_luks2_format(cd, hdr, i, cipher, vk->keylength);
		LUKS2_digest_assign(cd, hdr, i, 0, 1, 0);
		LUKS2_keyslot_assign(cd, hdr, i, 0, 1, 0);
		jobj1 = json_object_new_object();
		jobj2 = json_object_new_array();
		snprintf(num, sizeof(num), "%d", i);
		json_object_array_add(jobj2, json_object_new_string(num));
		json_object_object_add(jobj1, "keyslots", jobj2);
		json_object_object_add(jobj1, "offset", json_object_new_string(uint64_to_str(bignum, sizeof(bignum), &areas[i].offset)));
		json_object_object_add(jobj1, "length", json_object_new_string(uint64_to_str(bignum, sizeof(bignum), &areas[i].length)));
		json_object_object_add(jobj_areas, num, jobj1);
	}

	log_dbg("JSON: %s", json_object_to_json_string_ext(hdr->jobj, JSON_C_TO_STRING_PRETTY));
	return 0;
}
