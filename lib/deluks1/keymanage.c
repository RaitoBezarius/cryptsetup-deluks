/*
 * LUKS - Linux Unified Key Setup
 *
 * Copyright (C) 2004-2006, Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2009-2012, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2013-2014, Milan Broz
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

#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <uuid/uuid.h>

#include "deluks.h"
#include "af.h"
#include "internal.h"

/* Get size of struct deluks_phdr with all keyslots material space */
static size_t DELUKS_device_sectors(size_t keyLen)
{
	size_t keyslot_sectors, sector;
	int i;

	keyslot_sectors = AF_split_sectors(keyLen, DELUKS_STRIPES);
	sector = DELUKS_ALIGN_KEYSLOTS / SECTOR_SIZE;

	for (i = 0; i < DELUKS_NUMKEYS; i++) {
		sector = size_round_up(sector, DELUKS_ALIGN_KEYSLOTS / SECTOR_SIZE);
		sector += keyslot_sectors;
	}

	return sector;
}

int DELUKS_keyslot_area(const struct deluks_phdr *hdr,
	int keyslot,
	uint64_t *offset,
	uint64_t *length)
{
	if(keyslot >= DELUKS_NUMKEYS || keyslot < 0)
		return -EINVAL;

	*offset = hdr->keyblock[keyslot].keyMaterialOffset * SECTOR_SIZE;
	*length = AF_split_sectors(hdr->keyBytes, DELUKS_STRIPES) * SECTOR_SIZE;

	return 0;
}

static int DELUKS_check_device_size(struct crypt_device *ctx, size_t keyLength)
{
	struct device *device = crypt_metadata_device(ctx);
	uint64_t dev_sectors, hdr_sectors;

	if (!keyLength)
		return -EINVAL;

	if(device_size(device, &dev_sectors)) {
		log_dbg("Cannot get device size for device %s.", device_path(device));
		return -EIO;
	}

	dev_sectors >>= SECTOR_SHIFT;
	hdr_sectors = DELUKS_device_sectors(keyLength);
	log_dbg("Key length %zu, device size %" PRIu64 " sectors, header size %"
		PRIu64 " sectors.",keyLength, dev_sectors, hdr_sectors);

	if (hdr_sectors > dev_sectors) {
		log_err(ctx, _("Device %s is too small. (DELUKS requires at least %" PRIu64 " bytes.)\n"),
			device_path(device), hdr_sectors * SECTOR_SIZE);
		return -EINVAL;
	}

	return 0;
}

/* Check keyslot to prevent access outside of header and keyslot area */
static int DELUKS_check_keyslot_size(const struct deluks_phdr *phdr, unsigned int keyIndex)
{
	uint32_t secs_per_stripes;

	/* First sectors is the header itself */
	if (phdr->keyblock[keyIndex].keyMaterialOffset * SECTOR_SIZE < sizeof(*phdr)) {
		log_dbg("Invalid offset %" PRIu64 " in keyslot %u.",
			phdr->keyblock[keyIndex].keyMaterialOffset, keyIndex);
		return 1;
	}

	/* Ignore following check for detached header where offset can be zero. */
	if (phdr->payloadOffset == 0)
		return 0;

	if (phdr->payloadOffset <= phdr->keyblock[keyIndex].keyMaterialOffset) {
		log_dbg("Invalid offset %" PRIu64 " in keyslot %u (beyond data area offset %" PRIu64 ").",
			phdr->keyblock[keyIndex].keyMaterialOffset, keyIndex,
			phdr->payloadOffset);
		return 1;
	}

	secs_per_stripes = AF_split_sectors(phdr->keyBytes, phdr->keyblock[keyIndex].stripes);

	if (phdr->payloadOffset < (phdr->keyblock[keyIndex].keyMaterialOffset + secs_per_stripes)) {
		log_dbg("Invalid keyslot size %u (offset %" PRIu64 ", stripes %u) in "
			"keyslot %u (beyond data area offset %" PRIu64 ").",
			secs_per_stripes,
			phdr->keyblock[keyIndex].keyMaterialOffset,
			phdr->keyblock[keyIndex].stripes,
			keyIndex, phdr->payloadOffset);
		return 1;
	}

	return 0;
}

static const char *dbg_slot_state(crypt_keyslot_info ki)
{
	switch(ki) {
	case CRYPT_SLOT_INACTIVE:
		return "INACTIVE";
	case CRYPT_SLOT_ACTIVE:
		return "ACTIVE";
	case CRYPT_SLOT_ACTIVE_LAST:
		return "ACTIVE_LAST";
	case CRYPT_SLOT_INVALID:
	default:
		return "INVALID";
	}
}

/* Decrypt the options sub-header */
int DELUKS_decrypt_hdr_opt(struct deluks_phdr *hdr,
		  struct deluks_phdr_opt *hdr_opt_out,
		  struct volume_key *vk,
		  const char *cipher_name,
		  const char *cipher_mode,
		  struct crypt_device *ctx)
{
	char	iv[DELUKS_HDR_IV_LEN] = {};
	struct	crypt_cipher *cipher;
	char	*buf_in  = (char*)&hdr->options;
	char	*buf_out = (char*)hdr_opt_out;
	int i, r;
	char *c;
	char cipher_mode_direct[DELUKS_CIPHERMODE_L];

	/* Remove IV name from cipher mode name if present */
	strncpy(cipher_mode_direct, cipher_mode, MAX_CIPHER_LEN);
	c = strchr(cipher_mode_direct, '-');
	if (c)
		*c = '\0';

	/* TODO: Increase Master Key size and use a sub-key for header encryption, distinct from payload encryption */

	/* Initialize cipher struct */
	r = crypt_cipher_init(&cipher, cipher_name, cipher_mode_direct,
			      vk->key, vk->keylength);

	if (!r) {
		/* Decrypt options header */
		r = crypt_cipher_decrypt(cipher, buf_in, buf_out, sizeof(*hdr_opt_out),
					 iv, DELUKS_HDR_IV_LEN);

		crypt_cipher_destroy(cipher);

		/* Clean options sub-header endianess and strings & copy to real header */
		memcpy(hdr->magic, hdr_opt_out->magic, DELUKS_MAGIC_L);
		// TODO: Validate magic
		hdr->version	= hdr_opt_out->version	= ntohs(hdr_opt_out->version);
		hdr->keyBytes	= hdr_opt_out->keyBytes = ntohl(hdr_opt_out->keyBytes);
		hdr_opt_out->cipherName[DELUKS_CIPHERNAME_L - 1] = '\0';
		memcpy(hdr->cipherName, hdr_opt_out->cipherName, DELUKS_CIPHERNAME_L);
		hdr_opt_out->cipherMode[DELUKS_CIPHERMODE_L - 1] = '\0';		
		memcpy(hdr->cipherMode, hdr_opt_out->cipherMode, DELUKS_CIPHERMODE_L);
		hdr->payloadOffset	= hdr_opt_out->payloadOffset = ntohll(hdr_opt_out->payloadOffset);
		hdr_opt_out->payloadTotalSectors = ntohll(hdr_opt_out->payloadTotalSectors);
		hdr_opt_out->uuid[UUID_STRING_L - 1] = '\0';
		memcpy(hdr->uuid, hdr_opt_out->uuid, UUID_STRING_L);
		crypt_set_boot_priority(ctx, hdr_opt_out->bootPriority);

		for(i = 0; i < DELUKS_NUMKEYS; ++i) {

			hdr->keyblock[i].active = hdr_opt_out->keyblock[i].active = ntohl(hdr_opt_out->keyblock[i].active);
			if (DELUKS_check_keyslot_size(hdr, i)) {
				log_err(ctx, _("LUKS keyslot %u is invalid.\n"), i);
				r = -EINVAL;
			}
		}
	}

	crypt_memzero(iv, DELUKS_HDR_IV_LEN);
	return r;
}

/* Decrypt the options sub-header */
static int DELUKS_encrypt_hdr_opt(struct deluks_phdr *hdr,
		  struct deluks_phdr_opt *hdr_opt_out,
		  const struct volume_key *vk,
		  const char *cipher_name,
		  const char *cipher_mode,
		  struct crypt_device *ctx)
{
	char	iv[DELUKS_HDR_IV_LEN] = {};
	struct	crypt_cipher *cipher;
	char	*buf_in  = (char*)&hdr->options;
	char	*buf_out = (char*)hdr_opt_out;
	int r;
	char *c;
	char cipher_mode_direct[DELUKS_CIPHERMODE_L];


	/* Remove IV name from cipher mode name if present */
	strncpy(cipher_mode_direct, cipher_mode, MAX_CIPHER_LEN);
	c = strchr(cipher_mode_direct, '-');
	if (c)
		*c = '\0';

	/* WARNING: Modifying the encrypted options header requires changing the MK salt to avoid watermaking attacks */

	/* Initialize cipher struct */
	r = crypt_cipher_init(&cipher, cipher_name, cipher_mode_direct,
			      vk->key, vk->keylength);

	if (!r) {
		/* Decrypt options header */
		r = crypt_cipher_encrypt(cipher, buf_in, buf_out, sizeof(*hdr_opt_out),
					 iv, DELUKS_HDR_IV_LEN);
		crypt_cipher_destroy(cipher);

		/* Convert */
		// Done in caller: DELUKS_write_phdr()

	}

	crypt_memzero(iv, DELUKS_HDR_IV_LEN);
	return r;
}

int DELUKS_hdr_backup(const char *backup_file, struct crypt_device *ctx)
{
	struct device *device = crypt_metadata_device(ctx);
	struct deluks_phdr hdr;
	int r = 0, devfd = -1;
	ssize_t hdr_size;
	ssize_t buffer_size;
	char *buffer = NULL;

	r = DELUKS_read_phdr(&hdr, 1, 0, ctx);
	if (r)
		return r;

	hdr_size = DELUKS_device_sectors(hdr.keyBytes) << SECTOR_SHIFT;
	buffer_size = size_round_up(hdr_size, crypt_getpagesize());

	buffer = crypt_safe_alloc(buffer_size);
	if (!buffer || hdr_size < DELUKS_ALIGN_KEYSLOTS || hdr_size > buffer_size) {
		r = -ENOMEM;
		goto out;
	}

	log_dbg("Storing backup of header (%zu bytes) and keyslot area (%zu bytes).",
		sizeof(hdr), hdr_size - DELUKS_ALIGN_KEYSLOTS);

	log_dbg("Output backup file size: %zu bytes.", buffer_size);

	devfd = device_open(device, O_RDONLY);
	if(devfd == -1) {
		log_err(ctx, _("Device %s is not a valid DELUKS device.\n"), device_path(device));
		r = -EINVAL;
		goto out;
	}

	if (read_blockwise(devfd, device_block_size(device), buffer, hdr_size) < hdr_size) {
		r = -EIO;
		goto out;
	}
	close(devfd);

	/* Wipe unused area, so backup cannot contain old signatures */
	if (hdr.keyblock[0].keyMaterialOffset * SECTOR_SIZE == DELUKS_ALIGN_KEYSLOTS)
		memset(buffer + sizeof(hdr), 0, DELUKS_ALIGN_KEYSLOTS - sizeof(hdr));

	devfd = open(backup_file, O_CREAT|O_EXCL|O_WRONLY, S_IRUSR);
	if (devfd == -1) {
		if (errno == EEXIST)
			log_err(ctx, _("Requested header backup file %s already exists.\n"), backup_file);
		else
			log_err(ctx, _("Cannot create header backup file %s.\n"), backup_file);
		r = -EINVAL;
		goto out;
	}
	if (write_buffer(devfd, buffer, buffer_size) < buffer_size) {
		log_err(ctx, _("Cannot write header backup file %s.\n"), backup_file);
		r = -EIO;
		goto out;
	}
	close(devfd);

	r = 0;
out:
	if (devfd != -1)
		close(devfd);
	crypt_memzero(&hdr, sizeof(hdr));
	crypt_safe_free(buffer);
	return r;
}

int DELUKS_hdr_restore(
	const char *backup_file,
	struct deluks_phdr *hdr,
	struct crypt_device *ctx)
{
	struct device *device = crypt_metadata_device(ctx);
	int r = 0, devfd = -1, diff_uuid = 0;
	ssize_t buffer_size = 0;
	char *buffer = NULL, msg[200];
	struct deluks_phdr hdr_file;

	r = DELUKS_read_phdr_backup(backup_file, &hdr_file, 0, ctx);
	if (r == -ENOENT)
		return r;

	if (!r)
		buffer_size = DELUKS_device_sectors(hdr_file.keyBytes) << SECTOR_SHIFT;

	if (r || buffer_size < DELUKS_ALIGN_KEYSLOTS) {
		log_err(ctx, _("Backup file doesn't contain valid DELUKS header.\n"));
		r = -EINVAL;
		goto out;
	}

	buffer = crypt_safe_alloc(buffer_size);
	if (!buffer) {
		r = -ENOMEM;
		goto out;
	}

	devfd = open(backup_file, O_RDONLY);
	if (devfd == -1) {
		log_err(ctx, _("Cannot open header backup file %s.\n"), backup_file);
		r = -EINVAL;
		goto out;
	}

	if (read_buffer(devfd, buffer, buffer_size) < buffer_size) {
		log_err(ctx, _("Cannot read header backup file %s.\n"), backup_file);
		r = -EIO;
		goto out;
	}
	close(devfd);

	r = DELUKS_read_phdr(hdr, 0, 0, ctx);
	if (r == 0) {
		log_dbg("Device %s already contains DELUKS header, checking UUID and offset.", device_path(device));
		if(hdr->payloadOffset != hdr_file.payloadOffset ||
		   hdr->keyBytes != hdr_file.keyBytes) {
			log_err(ctx, _("Data offset or key size differs on device and backup, restore failed.\n"));
			r = -EINVAL;
			goto out;
		}
		if (memcmp(hdr->uuid, hdr_file.uuid, UUID_STRING_L))
			diff_uuid = 1;
	}

	if (snprintf(msg, sizeof(msg), _("Device %s %s%s"), device_path(device),
		 r ? _("does not contain DELUKS header. Replacing header can destroy data on that device.") :
		     _("already contains DELUKS header. Replacing header will destroy existing keyslots."),
		     diff_uuid ? _("\nWARNING: real device header has different UUID than backup!") : "") < 0) {
		r = -ENOMEM;
		goto out;
	}

	if (!crypt_confirm(ctx, msg)) {
		r = -EINVAL;
		goto out;
	}

	log_dbg("Storing backup of header (%zu bytes) and keyslot area (%zu bytes) to device %s.",
		sizeof(*hdr), buffer_size - DELUKS_ALIGN_KEYSLOTS, device_path(device));

	devfd = device_open(device, O_RDWR);
	if (devfd == -1) {
		if (errno == EACCES)
			log_err(ctx, _("Cannot write to device %s, permission denied.\n"),
				device_path(device));
		else
			log_err(ctx, _("Cannot open device %s.\n"), device_path(device));
		r = -EINVAL;
		goto out;
	}

	if (write_blockwise(devfd, device_block_size(device), buffer, buffer_size) < buffer_size) {
		r = -EIO;
		goto out;
	}
	close(devfd);

	/* Be sure to reload new data */
	r = DELUKS_read_phdr(hdr, 1, 0, ctx);
out:
	if (devfd != -1)
		close(devfd);
	crypt_safe_free(buffer);
	return r;
}

/* This routine should do some just basic recovery for known problems. */
static int _keyslot_repair(struct deluks_phdr *phdr, struct crypt_device *ctx)
{
	struct deluks_phdr temp_phdr;
	const unsigned char *sector = (const unsigned char*)phdr;
	struct volume_key *vk;
	uint64_t PBKDF2_per_sec = 1;
	int i, bad, r, need_write = 0;

	if (phdr->keyBytes != 16 && phdr->keyBytes != 32 && phdr->keyBytes != 64) {
		log_err(ctx, _("Non standard key size, manual repair required.\n"));
		return -EINVAL;
	}
	/* cryptsetup 1.0 did not align to 4k, cannot repair this one */
	if (phdr->keyblock[0].keyMaterialOffset < (DELUKS_ALIGN_KEYSLOTS / SECTOR_SIZE)) {
		log_err(ctx, _("Non standard keyslots alignment, manual repair required.\n"));
		return -EINVAL;
	}

	vk = crypt_alloc_volume_key(phdr->keyBytes, NULL);

	log_verbose(ctx, _("Repairing keyslots.\n"));

	log_dbg("Generating second header with the same parameters for check.");
	/* cipherName, cipherMode, hashSpec, uuid are already null terminated */
	/* payloadOffset - cannot check */
	r = DELUKS_generate_phdr(&temp_phdr, vk, phdr->cipherName, phdr->cipherMode,
			       phdr->hashSpec,phdr->uuid, DELUKS_STRIPES,
			       phdr->payloadOffset, 0,
			       0 /* TODO: support boot_priority */,
			       0 /* TODO: support iteration_num */,
			       1, &PBKDF2_per_sec,
			       1, ctx);
	if (r < 0) {
		log_err(ctx, _("Repair failed."));
		goto out;
	}

	for(i = 0; i < DELUKS_NUMKEYS; ++i) {
		if (phdr->keyblock[i].active == DELUKS_KEY_ENABLED)  {
			log_dbg("Skipping repair for active keyslot %i.", i);
			continue;
		}

		bad = 0;
		if (phdr->keyblock[i].keyMaterialOffset != temp_phdr.keyblock[i].keyMaterialOffset) {
			log_err(ctx, _("Keyslot %i: offset repaired (%u -> %u).\n"), i,
				(unsigned)phdr->keyblock[i].keyMaterialOffset,
				(unsigned)temp_phdr.keyblock[i].keyMaterialOffset);
			phdr->keyblock[i].keyMaterialOffset = temp_phdr.keyblock[i].keyMaterialOffset;
			bad = 1;
		}

		if (phdr->keyblock[i].stripes != temp_phdr.keyblock[i].stripes) {
			log_err(ctx, _("Keyslot %i: stripes repaired (%u -> %u).\n"), i,
				(unsigned)phdr->keyblock[i].stripes,
				(unsigned)temp_phdr.keyblock[i].stripes);
			phdr->keyblock[i].stripes = temp_phdr.keyblock[i].stripes;
			bad = 1;
		}

		/* Known case - MSDOS partition table signature */
		if (i == 6 && sector[0x1fe] == 0x55 && sector[0x1ff] == 0xaa) {
			log_err(ctx, _("Keyslot %i: bogus partition signature.\n"), i);
			bad = 1;
		}

		if(bad) {
			log_err(ctx, _("Keyslot %i: salt wiped.\n"), i);
			phdr->keyblock[i].active = DELUKS_KEY_DISABLED;
			memset(&phdr->keyblock[i].passwordSalt, 0x00, DELUKS_SALTSIZE);
			phdr->keyblock[i].passwordIterations = 0;
		}

		if (bad)
			need_write = 1;
	}

	if (need_write) {
		log_verbose(ctx, _("Writing DELUKS header to disk.\n"));
		r = DELUKS_write_phdr(phdr, NULL, ctx); // TEMP UNSUPPORTED
	}
out:
	crypt_free_volume_key(vk);
	crypt_memzero(&temp_phdr, sizeof(temp_phdr));
	return r;
}

static int _check_and_convert_hdr(const char *device,
				  struct deluks_phdr *hdr,
				  int require_deluks_device,
				  int repair,
				  struct crypt_device *ctx)
{
	int r = 0;
	unsigned int i;
	size_t blocksPerStripeSet, currentSector;
	uuid_t partitionUuid;
	// TODO: Support animal keyword

	if (crypt_hmac_size(crypt_get_hash_spec(ctx)) < DELUKS_DIGESTSIZE) {
		log_err(ctx, _("Requested DELUKS hash %s is not supported.\n"), crypt_get_hash_spec(ctx));
		return -EINVAL;
	}

	/* Header detected */
	uuid_generate(partitionUuid);	// TODO: Manage passed arguments
	uuid_unparse(partitionUuid, hdr->uuid);	// TODO: Manage passed arguments

	// TODO: Put crypt_get_hash_spec(ctx) & other in header
	hdr->payloadOffset      = DEFAULT_DISK_ALIGNMENT / SECTOR_SIZE; // TODO: Get real value from decrypted header
	hdr->keyBytes           = crypt_get_key_size(ctx);
	hdr->mkDigestIterations = crypt_get_iteration_num(ctx);

	// Temporary, indeed these fields represent the payload encryption settings, not the options sub-header encryption settings.
	memcpy(hdr->cipherName, crypt_get_options_cipher(ctx), DELUKS_CIPHERNAME_L);
	memcpy(hdr->cipherMode, crypt_get_options_cipher_mode(ctx), DELUKS_CIPHERMODE_L);
	memcpy(hdr->hashSpec, crypt_get_hash_spec(ctx), DELUKS_HASHSPEC_L);

	hdr->version            = 1;

	currentSector = DELUKS_ALIGN_KEYSLOTS / SECTOR_SIZE;
	blocksPerStripeSet = AF_split_sectors(crypt_get_key_size(ctx), DELUKS_STRIPES);
	for(i = 0; i < DELUKS_NUMKEYS; ++i) {
		hdr->keyblock[i].active             = DELUKS_KEY_ENABLED;
		hdr->keyblock[i].passwordIterations = crypt_get_iteration_num(ctx);
		hdr->keyblock[i].keyMaterialOffset  = currentSector;
		hdr->keyblock[i].stripes            = DELUKS_STRIPES;
		//hdr->options.keyblock[i].active     = hdr->keyblock[i].active;

		currentSector = size_round_up(currentSector + blocksPerStripeSet,
						DELUKS_ALIGN_KEYSLOTS / SECTOR_SIZE);
		hdr->payloadOffset = currentSector;
		if (DELUKS_check_keyslot_size(hdr, i)) {
			log_err(ctx, _("DELUKS keyslot %u is invalid.\n"), i);
			r = -EINVAL;
		}
	}

	/* Avoid unterminated strings */
	hdr->cipherName[DELUKS_CIPHERNAME_L - 1] = '\0';
	hdr->cipherMode[DELUKS_CIPHERMODE_L - 1] = '\0';
	hdr->uuid[UUID_STRING_L - 1] = '\0';

	if (repair) {
		if (r == -EINVAL)
			r = _keyslot_repair(hdr, ctx);
		else
			log_verbose(ctx, _("No known problems detected for DELUKS header.\n"));
	}

	// TODO: Replace by checksum check
	/*
	if(memcmp(hdr->magic, luksMagic, LUKS_MAGIC_L)) {
		log_dbg("LUKS header not detected.");
		if (require_luks_device)
			log_err(ctx, _("Device %s is not a valid DELUKS device.\n"), device);
		return -EINVAL;
	}
	*/

	return r;
}

static void _to_lower(char *str, unsigned max_len)
{
	for(; *str && max_len; str++, max_len--)
		if (isupper(*str))
			*str = tolower(*str);
}

static void DELUKS_fix_header_compatible(struct deluks_phdr *header)
{
	/* Old cryptsetup expects "sha1", gcrypt allows case insensistive names,
	 * so always convert hash to lower case in header */
	_to_lower(header->hashSpec, DELUKS_HASHSPEC_L);

	/* ECB mode does not use IV but dmcrypt silently allows it.
	 * Drop any IV here if ECB is used (that is not secure anyway).*/
	if (!strncmp(header->cipherMode, "ecb-", 4)) {
		memset(header->cipherMode, 0, DELUKS_CIPHERMODE_L);
		strcpy(header->cipherMode, "ecb");
	}
}

int DELUKS_read_phdr_backup(const char *backup_file,
			  struct deluks_phdr *hdr,
			  int require_deluks_device,
			  struct crypt_device *ctx)
{
	ssize_t hdr_size = sizeof(struct deluks_phdr);
	int devfd = 0, r = 0;

	log_dbg("Reading DELUKS header of size %d from backup file %s",
		(int)hdr_size, backup_file);

	devfd = open(backup_file, O_RDONLY);
	if(-1 == devfd) {
		log_err(ctx, _("Cannot open header backup file %s.\n"), backup_file);
		return -ENOENT;
	}

	if (read_buffer(devfd, hdr, hdr_size) < hdr_size)
		r = -EIO;
	else {
		DELUKS_fix_header_compatible(hdr);
		r = _check_and_convert_hdr(backup_file, hdr,
					   require_deluks_device, 0, ctx);
	}

	close(devfd);
	return r;
}

int DELUKS_read_phdr(struct deluks_phdr *hdr,
		   int require_deluks_device,
		   int repair,
		   struct crypt_device *ctx)
{
	struct device *device = crypt_metadata_device(ctx);
	ssize_t hdr_size = sizeof(struct deluks_phdr);
	int devfd = 0, r = 0;

	/* DELUKS header starts at offset 0, first keyslot on DELUKS_ALIGN_KEYSLOTS */
	assert(sizeof(struct deluks_phdr) <= DELUKS_ALIGN_KEYSLOTS);

	/* Stripes count cannot be changed without additional code fixes yet */
	assert(DELUKS_STRIPES == 4000);

	if (repair && !require_deluks_device)
		return -EINVAL;

	log_dbg("Reading DELUKS header of size %zu from device %s",
		hdr_size, device_path(device));

	devfd = device_open(device, O_RDONLY);
	if (devfd == -1) {
		log_err(ctx, _("Cannot open device %s.\n"), device_path(device));
		return -EINVAL;
	}

	if (read_blockwise(devfd, device_block_size(device), hdr, hdr_size) < hdr_size)
		r = -EIO;
	else
		r = _check_and_convert_hdr(device_path(device), hdr, require_deluks_device,
					   repair, ctx);

	if (!r)
		r = DELUKS_check_device_size(ctx, hdr->keyBytes);

	/*
	 * Cryptsetup 1.0.0 did not align keyslots to 4k (very rare version).
	 * Disable direct-io to avoid possible IO errors if underlying device
	 * has bigger sector size.
	 */
	if (!r && hdr->keyblock[0].keyMaterialOffset * SECTOR_SIZE < DELUKS_ALIGN_KEYSLOTS) {
		log_dbg("Old unaligned DELUKS keyslot detected, disabling direct-io.");
		device_disable_direct_io(device);
	}

	close(devfd);
	return r;
}

int DELUKS_write_phdr(struct deluks_phdr *hdr,
			const struct volume_key *vk,
		    struct crypt_device *ctx)
{
	struct device *device = crypt_metadata_device(ctx);
	ssize_t hdr_size = sizeof(struct deluks_phdr);
	int devfd = 0;
	unsigned int i;
	struct deluks_phdr convHdr;
	int r;
	uint64_t dev_sectors;

	log_dbg("Updating DeLUKS header of size %zu on device %s",
		sizeof(struct deluks_phdr), device_path(device));

	if (!vk) {
		log_err(ctx, _("Function not implemented.\n"));
		return -ENOSYS;
	}

	r = DELUKS_check_device_size(ctx, hdr->keyBytes);
	if (r)
		return r;

	if(device_size(device, &dev_sectors))
		return -EIO;
	dev_sectors >>= SECTOR_SHIFT;

	devfd = device_open(device, O_RDWR);
	if(-1 == devfd) {
		if (errno == EACCES)
			log_err(ctx, _("Cannot write to device %s, permission denied.\n"),
				device_path(device));
		else
			log_err(ctx, _("Cannot open device %s.\n"), device_path(device));
		return -EINVAL;
	}

	// Creating disk header by nuking all non-random and empty elements
	// DELUKS HEADER RANDOM ON DISK
	r = crypt_random_get(ctx, (char *)&convHdr, sizeof(convHdr), CRYPT_RND_NORMAL);
	if(r < 0) {
		log_err(ctx, _("Cannot create DELUKS header: random generator failed.\n"));
		close(devfd);
		return r;
	}

	// TODO: Check that we didn't end up looking like an MBR magic number

	// DELUKS HEADER KEPT ON DISK
	memcpy(&convHdr.mkDigest, hdr->mkDigest, DELUKS_DIGESTSIZE);
	memcpy(&convHdr.mkDigestSalt, hdr->mkDigestSalt, DELUKS_SALTSIZE);
	for(i = 0; i < DELUKS_NUMKEYS; ++i) {
		if(hdr->keyblock[i].active != DELUKS_KEY_DISABLED) {
			memcpy(&convHdr.keyblock[i].passwordSalt, hdr->keyblock[i].passwordSalt, DELUKS_SALTSIZE);
		}
	}

	// DELUKS ENCRYPTED OPTIONS FOR PAYLOAD MOUNTING
	/* Convert every uint16/32/64_t item to network byte order */
	// TODO: Add support based on payload (not header) user-provided enc settings.
	memcpy(convHdr.options.magic,hdr->magic,DELUKS_MAGIC_L);
	convHdr.options.version = htons(hdr->version);
	convHdr.options.keyBytes = htonl(hdr->keyBytes);
	memcpy(convHdr.options.cipherName, hdr->cipherName, DELUKS_CIPHERNAME_L);
	memcpy(convHdr.options.cipherMode, hdr->cipherMode, DELUKS_CIPHERMODE_L);
	convHdr.options.payloadOffset = htonll(hdr->payloadOffset);
	// TODO: Add support for unallocated space "partitions"
	// TODO: Define if offsets of those "partitions" are relative or absolute to the header start sector of the drive
	convHdr.options.payloadTotalSectors = htonll(dev_sectors-hdr->payloadOffset);
	memcpy(convHdr.options.uuid, hdr->uuid, UUID_STRING_L);
	convHdr.options.bootPriority = crypt_get_boot_priority(ctx);
	//log_dbg("<<DEBUG>> %s:%d UUID:          %.*s\n", __FILE__,__LINE__, UUID_STRING_L, hdr->uuid);
	
	for(i = 0; i < DELUKS_NUMKEYS; ++i) {
		convHdr.options.keyblock[i].active             = htonl(hdr->keyblock[i].active);
	}
	
	/* Encrypt options sub-header */
	r = DELUKS_encrypt_hdr_opt(&convHdr, &convHdr.options, vk, hdr->cipherName, hdr->cipherMode, ctx);
	if (r)
		log_err(ctx, _("Error during encryption of DeLUKS options sub-header. Disk unchanged.\n"));


	r = write_blockwise(devfd, device_block_size(device), &convHdr, hdr_size) < hdr_size ? -EIO : 0;
	if (r)
		log_err(ctx, _("Error during update of DELUKS header on device %s.\n"), device_path(device));
	close(devfd);

	/* Re-read header from disk to be sure that in-memory and on-disk data are the same. */
	// Don't do that, we also need to open the key for the DeLUKS header to be complete. And we may decrypt twice header_option.
	/*
	if (!r) {
		r = DELUKS_read_phdr(hdr, 1, 0, ctx);
		if (r)
			log_err(ctx, _("Error re-reading DELUKS header after update on device %s.\n"),
				device_path(device));
	}
	*/

	return r;
}

/* Check that kernel supports requested cipher by decryption of one sector */
static int DELUKS_check_cipher(struct deluks_phdr *hdr, struct crypt_device *ctx)
{
	int r;
	struct volume_key *empty_key;
	char buf[SECTOR_SIZE];

	log_dbg("Checking if cipher %s-%s is usable.", hdr->cipherName, hdr->cipherMode);

	empty_key = crypt_alloc_volume_key(hdr->keyBytes, NULL);
	if (!empty_key)
		return -ENOMEM;

	r = DELUKS_decrypt_from_storage(buf, sizeof(buf),
				      hdr->cipherName, hdr->cipherMode,
				      empty_key, 0, ctx);

	crypt_free_volume_key(empty_key);
	crypt_memzero(buf, sizeof(buf));
	return r;
}

int DELUKS_generate_phdr(struct deluks_phdr *header,
		       const struct volume_key *vk,
		       const char *cipherName, const char *cipherMode, const char *hashSpec,
		       const char *uuid, unsigned int stripes,
		       unsigned int alignPayload,
		       unsigned int alignOffset,
		       uint32_t boot_priority,
		       uint32_t iteration_num,
		       uint32_t iteration_time_ms,
		       uint64_t *PBKDF2_per_sec,
		       int detached_metadata_device,
		       struct crypt_device *ctx)
{
	unsigned int i = 0, hdr_sectors = DELUKS_device_sectors(vk->keylength);
	size_t blocksPerStripeSet, currentSector;
	int r;
	uuid_t partitionUuid;
	char deluksMagic[] = DELUKS_MAGIC;

	/* For separate metadata device allow zero alignment */
	if (alignPayload == 0 && !detached_metadata_device)
		alignPayload = DEFAULT_DISK_ALIGNMENT / SECTOR_SIZE;

	if (alignPayload && detached_metadata_device && alignPayload < hdr_sectors) {
		log_err(ctx, _("Data offset for detached DELUKS header must be "
			       "either 0 or higher than header size (%d sectors).\n"),
			       hdr_sectors);
		return -EINVAL;
	}

	if (crypt_hmac_size(hashSpec) < DELUKS_DIGESTSIZE) {
		log_err(ctx, _("Requested DELUKS hash %s is not supported.\n"), hashSpec);
		return -EINVAL;
	}

	if (uuid && uuid_parse(uuid, partitionUuid) == -1) {
		log_err(ctx, _("Wrong DELUKS UUID format provided.\n"));
		return -EINVAL;
	}
	if (!uuid)
		uuid_generate(partitionUuid);

	memset(header,0,sizeof(struct deluks_phdr));

	/* Set Magic */
	memcpy(header->magic,deluksMagic,DELUKS_MAGIC_L);
	header->version=1;
	strncpy(header->cipherName,cipherName,DELUKS_CIPHERNAME_L);
	strncpy(header->cipherMode,cipherMode,DELUKS_CIPHERMODE_L);
	strncpy(header->hashSpec,hashSpec,DELUKS_HASHSPEC_L);

	header->keyBytes=vk->keylength;

	//header->options.bootPriority=(uint8_t)boot_priority;

	DELUKS_fix_header_compatible(header);

	r = DELUKS_check_cipher(header, ctx);
	if (r < 0)
		return r;

	log_dbg("Generating DELUKS header version %d using hash %s, %s, %s, MK %d bytes",
		header->version, header->hashSpec ,header->cipherName, header->cipherMode,
		header->keyBytes);

	r = crypt_random_get(ctx, header->mkDigestSalt, DELUKS_SALTSIZE, CRYPT_RND_SALT);
	if(r < 0) {
		log_err(ctx, _("Cannot create DELUKS header: reading random salt failed.\n"));
		return r;
	}

	r = crypt_benchmark_kdf(ctx, "pbkdf2", header->hashSpec,
				"foo", 3, "bar", 3, PBKDF2_per_sec);
	if (r < 0) {
		log_err(ctx, _("Not compatible PBKDF2 options (using hash algorithm %s).\n"),
			header->hashSpec);
		return r;
	}

	/* Compute master key digest */
	iteration_time_ms /= 8;
	if (iteration_num == 0)
		iteration_num = (uint32_t)(*PBKDF2_per_sec/1024) * iteration_time_ms;
	header->mkDigestIterations = at_least(iteration_num,
					      DELUKS_MKD_ITERATIONS_MIN);

	r = crypt_pbkdf("pbkdf2", header->hashSpec, vk->key,vk->keylength,
			header->mkDigestSalt, DELUKS_SALTSIZE,
			header->mkDigest,DELUKS_DIGESTSIZE,
			header->mkDigestIterations);
	if(r < 0) {
		log_err(ctx, _("Cannot create DELUKS header: header digest failed (using hash %s).\n"),
			header->hashSpec);
		return r;
	}

	currentSector = DELUKS_ALIGN_KEYSLOTS / SECTOR_SIZE;
	blocksPerStripeSet = AF_split_sectors(vk->keylength, stripes);
	for(i = 0; i < DELUKS_NUMKEYS; ++i) {
		header->keyblock[i].active = DELUKS_KEY_DISABLED;
		header->keyblock[i].keyMaterialOffset = currentSector;
		header->keyblock[i].stripes = stripes;
		currentSector = size_round_up(currentSector + blocksPerStripeSet,
						DELUKS_ALIGN_KEYSLOTS / SECTOR_SIZE);
	}

	if (detached_metadata_device) {
		/* for separate metadata device use alignPayload directly */
		header->payloadOffset = alignPayload;
	} else {
		/* alignOffset - offset from natural device alignment provided by topology info */
		currentSector = size_round_up(currentSector, alignPayload);
		header->payloadOffset = currentSector + alignOffset;
	}

        uuid_unparse(partitionUuid, header->uuid);

	log_dbg("Data offset %" PRIu64 ", UUID %s, digest iterations %" PRIu32,
		header->payloadOffset, header->uuid, header->mkDigestIterations);

	return 0;
}

int DELUKS_hdr_uuid_set(
	struct deluks_phdr *hdr,
	const char *uuid,
	struct crypt_device *ctx)
{
	uuid_t partitionUuid;

	if (uuid && uuid_parse(uuid, partitionUuid) == -1) {
		log_err(ctx, _("Wrong DELUKS UUID format provided.\n"));
		return -EINVAL;
	}
	if (!uuid)
		uuid_generate(partitionUuid);

	uuid_unparse(partitionUuid, hdr->uuid);

	return DELUKS_write_phdr(hdr, NULL, ctx); // TEMP UNSUPPORTED
}

int DELUKS_set_key(unsigned int keyIndex,
		 const char *password, size_t passwordLen,
		 struct deluks_phdr *hdr, struct volume_key *vk,
		 uint32_t iteration_time_ms __attribute__ ((unused)),
		 uint64_t *PBKDF2_per_sec __attribute__ ((unused)),
		 struct crypt_device *ctx)
{
	struct volume_key *derived_key;
	char *AfKey = NULL;
	size_t AFEKSize;
	uint64_t PBKDF2_temp __attribute__ ((unused));
	int r;

	if(hdr->keyblock[keyIndex].active != DELUKS_KEY_DISABLED) {
		log_err(ctx, _("Key slot %d active, purge first.\n"), keyIndex);
		return -EINVAL;
	}

	/* DELUKS keyslot has always at least 4000 stripes accoding to specification */
	if(hdr->keyblock[keyIndex].stripes < 4000) {
	        log_err(ctx, _("Key slot %d material includes too few stripes. Header manipulation?\n"),
			keyIndex);
	         return -EINVAL;
	}

	log_dbg("Calculating data for key slot %d", keyIndex);

	/*
	 * Avoid floating point operation
	 * Final iteration count is at least DELUKS_SLOT_ITERATIONS_MIN
	 */
	// For DELUKS: key slot PBKDF2 iterations = mkDigest PBKDF2 iterations
	hdr->keyblock[keyIndex].passwordIterations = at_least(hdr->mkDigestIterations,
							      DELUKS_SLOT_ITERATIONS_MIN);

	log_dbg("Key slot %d use %" PRIu32 " password iterations.", keyIndex, hdr->keyblock[keyIndex].passwordIterations);

	derived_key = crypt_alloc_volume_key(hdr->keyBytes, NULL);
	if (!derived_key)
		return -ENOMEM;

	r = crypt_random_get(ctx, hdr->keyblock[keyIndex].passwordSalt,
		       DELUKS_SALTSIZE, CRYPT_RND_SALT);
	if (r < 0)
		goto out;

	r = crypt_pbkdf("pbkdf2", hdr->hashSpec, password, passwordLen,
			hdr->keyblock[keyIndex].passwordSalt, DELUKS_SALTSIZE,
			derived_key->key, hdr->keyBytes,
			hdr->keyblock[keyIndex].passwordIterations);
	if (r < 0)
		goto out;

	/*
	 * AF splitting, the masterkey stored in vk->key is split to AfKey
	 */
	assert(vk->keylength == hdr->keyBytes);
	AFEKSize = AF_split_sectors(vk->keylength, hdr->keyblock[keyIndex].stripes) * SECTOR_SIZE;
	AfKey = crypt_safe_alloc(AFEKSize);
	if (!AfKey) {
		r = -ENOMEM;
		goto out;
	}

	log_dbg("Using hash %s for AF in key slot %d, %d stripes",
		hdr->hashSpec, keyIndex, hdr->keyblock[keyIndex].stripes);
	r = AF_split(vk->key,AfKey,vk->keylength,hdr->keyblock[keyIndex].stripes,hdr->hashSpec);
	if (r < 0)
		goto out;

	log_dbg("Updating key slot %d [%#" PRIx64 "] area.", keyIndex,
		hdr->keyblock[keyIndex].keyMaterialOffset << 9);
	/* Encryption via dm */
	r = DELUKS_encrypt_to_storage(AfKey,
				    AFEKSize,
				    hdr->cipherName, hdr->cipherMode,
				    derived_key,
				    hdr->keyblock[keyIndex].keyMaterialOffset,
				    ctx);
	if (r < 0)
		goto out;

	/* Mark the key as active in phdr */
	r = DELUKS_keyslot_set(hdr, (int)keyIndex, 1);
	if (r < 0)
		goto out;

	r = DELUKS_write_phdr(hdr, vk, ctx);
	if (r < 0)
		goto out;

	r = 0;
out:
	crypt_safe_free(AfKey);
	crypt_free_volume_key(derived_key);
	return r;
}

/* Check whether a volume key is invalid. */
int DELUKS_verify_volume_key(const struct deluks_phdr *hdr,
			   const struct volume_key *vk)
{
	char checkHashBuf[DELUKS_DIGESTSIZE];

	if (crypt_pbkdf("pbkdf2", hdr->hashSpec, vk->key, vk->keylength,
			hdr->mkDigestSalt, DELUKS_SALTSIZE,
			checkHashBuf, DELUKS_DIGESTSIZE,
			hdr->mkDigestIterations) < 0)
		return -EINVAL;

	if (memcmp(checkHashBuf, hdr->mkDigest, DELUKS_DIGESTSIZE))
		return -EPERM;

	return 0;
}

/* Try to open a particular key slot and decipher options */
static int DELUKS_open_key(unsigned int keyIndex,
		  const char *password,
		  size_t passwordLen,
		  struct deluks_phdr *hdr,
		  struct volume_key *vk,
		  struct crypt_device *ctx)
{
	crypt_keyslot_info ki = DELUKS_keyslot_info(hdr, keyIndex);
	struct volume_key *derived_key;
	char *AfKey;
	size_t AFEKSize;
	int r;

	log_dbg("Trying to open key slot %d [%s].", keyIndex,
		dbg_slot_state(ki));

	if (ki < CRYPT_SLOT_ACTIVE)
		return -ENOENT;

	derived_key = crypt_alloc_volume_key(hdr->keyBytes, NULL);
	if (!derived_key)
		return -ENOMEM;

	assert(vk->keylength == hdr->keyBytes);
	AFEKSize = AF_split_sectors(vk->keylength, hdr->keyblock[keyIndex].stripes) * SECTOR_SIZE;
	AfKey = crypt_safe_alloc(AFEKSize);
	if (!AfKey) {
		r = -ENOMEM;
		goto out;
	}

	r = crypt_pbkdf("pbkdf2", hdr->hashSpec, password, passwordLen,
			hdr->keyblock[keyIndex].passwordSalt, DELUKS_SALTSIZE,
			derived_key->key, hdr->keyBytes,
			hdr->keyblock[keyIndex].passwordIterations);
	if (r < 0)
		goto out;

	log_dbg("Reading key slot %d area.", keyIndex);
	r = DELUKS_decrypt_from_storage(AfKey,
				      AFEKSize,
				      hdr->cipherName, hdr->cipherMode,
				      derived_key,
				      hdr->keyblock[keyIndex].keyMaterialOffset,
				      ctx);
	if (r < 0)
		goto out;

	r = AF_merge(AfKey,vk->key,vk->keylength,hdr->keyblock[keyIndex].stripes,hdr->hashSpec);
	if (r < 0)
		goto out;

	r = DELUKS_verify_volume_key(hdr, vk);

	/* Allow only empty passphrase with null cipher */
	if (!r && !strcmp(hdr->cipherName, "cipher_null") && passwordLen)
		r = -EPERM;

	if (!r)
		log_verbose(ctx, _("Key slot %d unlocked.\n"), keyIndex);

out:
	crypt_safe_free(AfKey);
	crypt_free_volume_key(derived_key);
	return r;
}

int DELUKS_open_key_with_hdr(int keyIndex,
			   const char *password,
			   size_t passwordLen,
			   struct deluks_phdr *hdr,
			   struct volume_key **vk,
			   struct crypt_device *ctx)
{
	unsigned int i;
	int r;

	*vk = crypt_alloc_volume_key(hdr->keyBytes, NULL);

	if (keyIndex >= 0) {
		r = DELUKS_open_key(keyIndex, password, passwordLen, hdr, *vk, ctx);
		return (r < 0) ? r : keyIndex;
	}

	for(i = 0; i < DELUKS_NUMKEYS; i++) {
		r = DELUKS_open_key(i, password, passwordLen, hdr, *vk, ctx);
		if(r == 0)
			return i;

		/* Do not retry for errors that are no -EPERM or -ENOENT,
		   former meaning password wrong, latter key slot inactive */
		if ((r != -EPERM) && (r != -ENOENT))
			return r;
	}
	/* Warning, early returns above */
	log_err(ctx, _("No key available with this passphrase.\n"));
	return -EPERM;
}

int DELUKS_del_key(unsigned int keyIndex,
		 struct deluks_phdr *hdr,
		 struct crypt_device *ctx)
{
	struct device *device = crypt_metadata_device(ctx);
	unsigned int startOffset, endOffset;
	int r;

	r = DELUKS_read_phdr(hdr, 1, 0, ctx);
	if (r)
		return r;

	r = DELUKS_keyslot_set(hdr, keyIndex, 0);
	if (r) {
		log_err(ctx, _("Key slot %d is invalid, please select keyslot between 0 and %d.\n"),
			keyIndex, DELUKS_NUMKEYS - 1);
		return r;
	}

	/* secure deletion of key material */
	startOffset = hdr->keyblock[keyIndex].keyMaterialOffset;
	endOffset = startOffset + AF_split_sectors(hdr->keyBytes, hdr->keyblock[keyIndex].stripes);

	r = crypt_wipe(device, startOffset * SECTOR_SIZE,
		       (endOffset - startOffset) * SECTOR_SIZE,
		       CRYPT_WIPE_DISK, 0);
	if (r) {
		if (r == -EACCES) {
			log_err(ctx, _("Cannot write to device %s, permission denied.\n"),
				device_path(device));
			r = -EINVAL;
		} else
			log_err(ctx, _("Cannot wipe device %s.\n"),
				device_path(device));
		return r;
	}

	/* Wipe keyslot info */
	memset(&hdr->keyblock[keyIndex].passwordSalt, 0, DELUKS_SALTSIZE);
	hdr->keyblock[keyIndex].passwordIterations = 0;

	r = DELUKS_write_phdr(hdr, NULL, ctx); // TEMP UNSUPPORTED

	return r;
}

crypt_keyslot_info DELUKS_keyslot_info(struct deluks_phdr *hdr, int keyslot)
{
	int i;

	if(keyslot >= DELUKS_NUMKEYS || keyslot < 0)
		return CRYPT_SLOT_INVALID;

	if (hdr->keyblock[keyslot].active == DELUKS_KEY_DISABLED)
		return CRYPT_SLOT_INACTIVE;

	if (hdr->keyblock[keyslot].active != DELUKS_KEY_ENABLED)
		return CRYPT_SLOT_INVALID;

	for(i = 0; i < DELUKS_NUMKEYS; i++)
		if(i != keyslot && hdr->keyblock[i].active == DELUKS_KEY_ENABLED)
			return CRYPT_SLOT_ACTIVE;

	return CRYPT_SLOT_ACTIVE_LAST;
}

int DELUKS_keyslot_find_empty(struct deluks_phdr *hdr)
{
	int i;

	for (i = 0; i < DELUKS_NUMKEYS; i++)
		if(hdr->keyblock[i].active == DELUKS_KEY_DISABLED)
			break;

	if (i == DELUKS_NUMKEYS)
		return -EINVAL;

	return i;
}

int DELUKS_keyslot_active_count(struct deluks_phdr *hdr)
{
	int i, num = 0;

	for (i = 0; i < DELUKS_NUMKEYS; i++)
		if(hdr->keyblock[i].active == DELUKS_KEY_ENABLED)
			num++;

	return num;
}

int DELUKS_keyslot_set(struct deluks_phdr *hdr, int keyslot, int enable)
{
	crypt_keyslot_info ki = DELUKS_keyslot_info(hdr, keyslot);

	if (ki == CRYPT_SLOT_INVALID)
		return -EINVAL;

	hdr->keyblock[keyslot].active = enable ? DELUKS_KEY_ENABLED : DELUKS_KEY_DISABLED;
	log_dbg("Key slot %d was %s in DELUKS header.", keyslot, enable ? "enabled" : "disabled");
	return 0;
}

int DELUKS1_activate(struct crypt_device *cd,
		   const char *name,
		   struct volume_key *vk,
		   uint32_t flags)
{
	int r;
	char *dm_cipher = NULL;
	enum devcheck device_check;
	struct crypt_dm_active_device dmd = {
		.target = DM_CRYPT,
		.uuid   = crypt_get_uuid(cd),
		.flags  = flags,
		.size   = 0,
		.data_device = crypt_data_device(cd),
		.u.crypt = {
			.cipher = NULL,
			.vk     = vk,
			.offset = crypt_get_data_offset(cd),
			.iv_offset = 0,
		}
	};

	if (dmd.flags & CRYPT_ACTIVATE_SHARED)
		device_check = DEV_SHARED;
	else
		device_check = DEV_EXCL;

	r = device_block_adjust(cd, dmd.data_device, device_check,
				 dmd.u.crypt.offset, &dmd.size, &dmd.flags);
	if (r)
		return r;

	r = asprintf(&dm_cipher, "%s-%s", crypt_get_cipher(cd), crypt_get_cipher_mode(cd));
	if (r < 0)
		return -ENOMEM;

	dmd.u.crypt.cipher = dm_cipher;
	r = dm_create_device(cd, name, CRYPT_DELUKS1, &dmd, 0);

	free(dm_cipher);
	return r;
}
