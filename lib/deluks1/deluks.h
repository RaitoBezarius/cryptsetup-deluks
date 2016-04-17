/*
 * DELUKS - Linux Unified Key Setup
 *
 * Copyright (C) 2004-2006, Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2009-2012, Red Hat, Inc. All rights reserved.
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

#ifndef INCLUDED_CRYPTSETUP_DELUKS_DELUKS_H
#define INCLUDED_CRYPTSETUP_DELUKS_DELUKS_H

/*
 * DELUKS partition header
 */

#include "libcryptsetup.h"

#define DELUKS_CIPHERNAME_L 32
#define DELUKS_CIPHERMODE_L 32
#define DELUKS_HASHSPEC_L 32
#define DELUKS_DIGESTSIZE 20 // since SHA1
#define DELUKS_HMACSIZE 32
#define DELUKS_SALTSIZE 32
#define DELUKS_NUMKEYS 8
#define DELUKS_HDR_IV_LEN 16

// Minimal number of iterations
#define DELUKS_MKD_ITERATIONS_MIN  1000
#define DELUKS_SLOT_ITERATIONS_MIN 1000

#define DELUKS_KEY_DISABLED_OLD 0
#define DELUKS_KEY_ENABLED_OLD 0xCAFE

#define DELUKS_KEY_DISABLED 0x0000DEAD
#define DELUKS_KEY_ENABLED  0x00AC71F3

#define DELUKS_STRIPES 4000

// partition header starts with magic
#define DELUKS_MAGIC {'L','U','K','S', 0xba, 0xbe};
#define DELUKS_MAGIC_L 6

/* Actually we need only 37, but we don't want struct autoaligning to kick in */
#define UUID_STRING_L 40

/* Offset to keyslot area [in bytes] */
#define DELUKS_ALIGN_KEYSLOTS 4096

/* Portable uint64_t endianess converter */
#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))

/* Any integer values are stored in network byte order on disk and must be
converted */

struct volume_key;
struct device_backend;

// DELUKS header structure (TODO: -> doc)
// Decrypted (after processing): DELUKS header contains all LUKS header elements, but possibly at different positions in memory
// Encryped  (on disk): DELUKS header contains only:
// - 3 LUKS header elements useful yet random-looking;
// - Other LUKS options become meaningless random data (RANDOM ON DISK);
// - An options block encrypted with DELUKS header encryption settings. These header encryption settings can be:
//   - DELUKS version defaults (automatically tested)
//   - Older DELUKS version defaults (automatically tested by DELUKS as a fallback at mouting)
//   - Shortcut animal keyword (must be manually provided at mounting)
//   - Command-line provided options (must be manually provided at mounting)
// Payload encryption settings (stored in encrypted header) can be different than DELUKS header encryption settings.
// This structure definition eases compatibility with LUKS codebase

struct deluks_phdr_opt {
	char		magic[DELUKS_MAGIC_L];          // RANDOM ON DISK
	uint16_t	version;
	uint32_t	keyBytes;
	char		cipherName[DELUKS_CIPHERNAME_L];
	char		cipherMode[DELUKS_CIPHERMODE_L];
	uint64_t	payloadOffset;
	uint64_t	payloadTotalSectors;
	char		uuid[UUID_STRING_L];
	uint8_t 	bootPriority;
	struct __attribute__((__packed__)) {
		uint32_t active;
	} keyblock[DELUKS_NUMKEYS];
	uint8_t  	_padding[347];
} __attribute__((__packed__));

struct deluks_phdr {
	char		magic[DELUKS_MAGIC_L];          // RANDOM ON DISK
	uint16_t	version;                        // RANDOM ON DISK
	char		cipherName[DELUKS_CIPHERNAME_L];// RANDOM ON DISK
	char		cipherMode[DELUKS_CIPHERMODE_L];// RANDOM ON DISK
	char		hashSpec[DELUKS_HASHSPEC_L];    // RANDOM ON DISK
	uint64_t	payloadOffset;                  // RANDOM ON DISK
	uint32_t	keyBytes;                       // RANDOM ON DISK
	char		mkDigest[DELUKS_DIGESTSIZE];
	char		mkDigestSalt[DELUKS_SALTSIZE];
	uint32_t	mkDigestIterations;             // RANDOM ON DISK
	char		uuid[UUID_STRING_L];            // RANDOM ON DISK
	uint8_t 	_padding1[300]; /* Special padding instead of keyblock[3] salt at the position of Master Boot Record magic number */

	/* key information blocks, 512 bytes */
	struct __attribute__((__packed__)) {
		uint32_t active;                        // RANDOM ON DISK
		uint32_t passwordIterations;            // RANDOM ON DISK
		char     passwordSalt[DELUKS_SALTSIZE];
		uint64_t keyMaterialOffset;             // RANDOM ON DISK
		uint32_t stripes;                       // RANDOM ON DISK
	} keyblock[DELUKS_NUMKEYS];
    uint8_t _padding2[96];

	/* encrypted part, 512 bytes */
	struct deluks_phdr_opt options;
} __attribute__((__packed__));



int DELUKS_verify_volume_key(const struct deluks_phdr *hdr,
			   const struct volume_key *vk);

int DELUKS_generate_phdr(
	struct deluks_phdr *header,
	const struct volume_key *vk,
	const char *cipherName,
	const char *cipherMode,
	const char *hashSpec,
	const char *uuid,
	unsigned int stripes,
	unsigned int alignPayload,
	unsigned int alignOffset,
	uint32_t boot_priority,
	uint32_t iteration_num,
	uint32_t iteration_time_ms,
	uint64_t *PBKDF2_per_sec,
	int detached_metadata_device,
	struct crypt_device *ctx);

int DELUKS_read_phdr(
	struct deluks_phdr *hdr,
	int require_deluks_device,
	int repair,
	struct crypt_device *ctx);

int DELUKS_read_phdr_backup(
	const char *backup_file,
	struct deluks_phdr *hdr,
	int require_deluks_device,
	struct crypt_device *ctx);

int DELUKS_hdr_uuid_set(
	struct deluks_phdr *hdr,
	const char *uuid,
	struct crypt_device *ctx);

int DELUKS_hdr_backup(
	const char *backup_file,
	struct crypt_device *ctx);

int DELUKS_hdr_restore(
	const char *backup_file,
	struct deluks_phdr *hdr,
	struct crypt_device *ctx);

int DELUKS_write_phdr(
	struct deluks_phdr *hdr,
	const struct volume_key *vk,
	struct crypt_device *ctx);

int DELUKS_set_key(
	unsigned int keyIndex,
	const char *password,
	size_t passwordLen,
	struct deluks_phdr *hdr,
	struct volume_key *vk,
	uint32_t iteration_time_ms,
	uint64_t *PBKDF2_per_sec,
	struct crypt_device *ctx);

int DELUKS_open_key_with_hdr(
	int keyIndex,
	const char *password,
	size_t passwordLen,
	struct deluks_phdr *hdr,
	struct volume_key **vk,
	struct crypt_device *ctx);

int DELUKS_del_key(
	unsigned int keyIndex,
	struct deluks_phdr *hdr,
	struct crypt_device *ctx);

crypt_keyslot_info DELUKS_keyslot_info(struct deluks_phdr *hdr, int keyslot);
int DELUKS_keyslot_find_empty(struct deluks_phdr *hdr);
int DELUKS_keyslot_active_count(struct deluks_phdr *hdr);
int DELUKS_keyslot_set(struct deluks_phdr *hdr, int keyslot, int enable);
int DELUKS_keyslot_area(const struct deluks_phdr *hdr,
	int keyslot,
	uint64_t *offset,
	uint64_t *length);

int DELUKS_encrypt_to_storage(
	char *src, size_t srcLength,
	const char *cipher,
	const char *cipher_mode,
	struct volume_key *vk,
	unsigned int sector,
	struct crypt_device *ctx);

int DELUKS_decrypt_from_storage(
	char *dst, size_t dstLength,
	const char *cipher,
	const char *cipher_mode,
	struct volume_key *vk,
	unsigned int sector,
	struct crypt_device *ctx);

int DELUKS1_activate(struct crypt_device *cd,
		   const char *name,
		   struct volume_key *vk,
		   uint32_t flags);

#endif
