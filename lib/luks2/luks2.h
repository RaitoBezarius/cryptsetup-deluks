/*
 * LUKS - Linux Unified Key Setup v2
 *
 * Copyright (C) 2015, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2015, Milan Broz. All rights reserved.
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

#ifndef _CRYPTSETUP_LUKS2_ONDISK_H
#define _CRYPTSETUP_LUKS2_ONDISK_H

#include <stdint.h>

#define LUKS2_MAGIC_1ST "LUKS\xba\xbe"
#define LUKS2_MAGIC_2ND "SKUL\xba\xbe"
#define LUKS2_MAGIC_L 6
#define LUKS2_UUID_L 40
#define LUKS2_LABEL_L 48
#define LUKS2_SALT_L 64
#define LUKS2_CHECKSUM_ALG_L 32
#define LUKS2_CHECKSUM_L 64

#define LUKS2_KEYSLOTS_MAX       32
#define LUKS2_KEYSLOTS_WITH_AREAS 8

/*
 * LUKS2 header on-disk.
 *
 * Binary header is followed by JSON area.
 * JSON area is followed by keyslot area and data area,
 * these are described in JSON metadata.
 *
 * Note: uuid, csum_alg are intentionally on the same offset as LUKS1
 * (checksum alg replaces hash in LUKS1)
 *
 * String (char) should be zero terminated.
 * Padding should be wiped.
 * Checksum is calculated with csum zeroed (+ full JSON area).
 */
/* FIXME: add flags? maintained by other system etc */
struct luks2_hdr_disk {
	char		magic[LUKS2_MAGIC_L];
	uint16_t	version;	/* Version 2 */
	uint64_t	hdr_size;	/* in bytes, including JSON area */
	uint64_t	seqid;		/* increased on every update */
	char		label[LUKS2_LABEL_L];
	char		checksum_alg[LUKS2_CHECKSUM_ALG_L];
	uint8_t		salt[LUKS2_SALT_L]; /* unique for every header/offset */
	char		uuid[LUKS2_UUID_L];
	char		subsystem[LUKS2_LABEL_L]; /* owner subsystem label */
	char		_padding[192];
	uint8_t		csum[LUKS2_CHECKSUM_L];
	/* JSON area starts here */
} __attribute__ ((packed));

/*
 * LUKS2 header in-memory.
 */
typedef struct json_object json_object;
struct luks2_hdr {
	size_t		hdr_size;
	uint64_t	seqid;
	unsigned int	version;
	char		label[LUKS2_LABEL_L];
	char		subsystem[LUKS2_LABEL_L];
	char		checksum_alg[LUKS2_CHECKSUM_ALG_L];
	uint8_t		salt1[LUKS2_SALT_L];
	uint8_t		salt2[LUKS2_SALT_L];
	char		uuid[LUKS2_UUID_L];
	json_object	*jobj;
};

/*
 * Supportable header sizes (hdr_disk + JSON area)
 * Also used as offset for the 2nd header.
 */
#define LUKS2_HDR_16K_LEN 0x4000

#define LUKS2_HDR_BIN_LEN sizeof(struct luks2_hdr_disk)

int LUKS2_hdr_read(struct crypt_device *cd, struct luks2_hdr *hdr);
int LUKS2_hdr_write(struct crypt_device *cd, struct luks2_hdr *hdr);
int LUKS2_hdr_dump(struct crypt_device *cd, struct luks2_hdr *hdr);

int LUKS2_hdr_uuid(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	const char *uuid);

void LUKS2_hdr_free(struct luks2_hdr *hdr);

int LUKS2_hdr_backup(struct crypt_device *cd, struct luks2_hdr *hdr,
		     const char *backup_file);
int LUKS2_hdr_restore(struct crypt_device *cd, struct luks2_hdr *hdr,
		     const char *backup_file);

/*
 * Generic LUKS2 keyslot
 */
int LUKS2_keyslot_open(struct crypt_device *cd,
	int keyslot,
	const char *password,
	size_t password_len,
	struct volume_key **vk);

int LUKS2_keyslot_store(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	const char *password,
	size_t password_len,
	const struct volume_key *vk);

int LUKS2_keyslot_wipe(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot);

int LUKS2_keyslot_dump(struct crypt_device *cd,
	int keyslot);

int LUKS2_keyslot_create(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	const char *type,
	const char *json,
	int commit);

int LUKS2_keyslot_json_get(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	const char **json);

int LUKS2_keyslot_json_set(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	const char *json);

int LUKS2_keyslot_assign(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	int segment,
	int assign,
	int commit);

crypt_keyslot_priority LUKS2_keyslot_priority_get(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot);

int LUKS2_keyslot_priority_set(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	crypt_keyslot_priority priority,
	int commit);

/*
 * Generic LUKS2 digest
 */
int LUKS2_digest_verify(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct volume_key *vk,
	int keyslot);

int LUKS2_digest_dump(struct crypt_device *cd,
	int digest);

int LUKS2_digest_json_get(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int digest,
	const char **json);

int LUKS2_digest_json_set(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int digest,
	const char *json);

int LUKS2_digest_assign(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	int digest,
	int assign,
	int commit);


/*
 * LUKS2 generic
 */
int LUKS2_activate(struct crypt_device *cd,
	const char *name,
	struct volume_key *vk,
	uint32_t flags);

int LUKS2_keyslot_luks2_format(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	const char *cipher,
	size_t keylength);

int LUKS2_generate_hdr(
	struct crypt_device *cd,
	struct luks2_hdr *hdr,
	const struct volume_key *vk,
	const char *cipherName,
	const char *cipherMode,
	const char *uuid,
	unsigned int alignPayload,
	unsigned int alignOffset,
	int detached_metadata_device);

uint64_t LUKS2_get_data_offset(struct luks2_hdr *hdr);
const char *LUKS2_get_cipher(struct luks2_hdr *hdr, unsigned int segment);
int LUKS2_get_volume_key_size(struct luks2_hdr *hdr, unsigned int segment);
int LUKS2_keyslot_find_empty(struct luks2_hdr *hdr, const char *type);
int LUKS2_keyslot_active_count(struct luks2_hdr *hdr);
crypt_keyslot_info LUKS2_keyslot_info(struct luks2_hdr *hdr, int keyslot);
int LUKS2_keyslot_area(struct luks2_hdr *hdr,
	int keyslot,
	uint64_t *offset,
	uint64_t *length);

struct luks_phdr;
int LUKS2_luks1_to_luks2(struct crypt_device *cd, struct luks_phdr *hdr1, struct luks2_hdr *hdr2);
int LUKS2_luks2_to_luks1(struct crypt_device *cd, struct luks2_hdr *hdr2, struct luks_phdr *hdr1);

void hexprint_base64(struct crypt_device *cd, json_object *jobj,
		     const char *sep, const char *line_sep);

json_object *parse_json_len(const char *json_area, int length, int *end_offset);
uint64_t json_object_get_uint64(json_object *jobj);
uint32_t json_object_get_uint32(json_object *jobj);

#endif
