/*
 * LUKS - Linux Unified Key Setup v2
 *
 * Copyright (C) 2015-2016, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2015-2016, Milan Broz. All rights reserved.
 * Copyright (C) 2015-2016, Ondrej Kozina. All rights reserved.
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
#include <ctype.h>
#include <uuid/uuid.h>

struct interval {
	uint64_t offset;
	uint64_t length;
};

void hexprint_base64(struct crypt_device *cd, json_object *jobj,
		     const char *sep, const char *line_sep)
{
	char *buf = NULL;
	size_t buf_len;
	unsigned int i;

	if (!base64_decode_alloc(json_object_get_string(jobj),
				 json_object_get_string_len(jobj),
				 &buf, &buf_len))
		return;

	for (i = 0; i < buf_len / 2; i++)
		log_std(cd, "%02hhx%s", buf[i], sep);
	log_std(cd, "\n\t%s", line_sep);
	for (i = buf_len / 2; i < buf_len; i++)
		log_std(cd, "%02hhx%s", buf[i], sep);
	log_std(cd, "\n");
	free(buf);
}

/*
 * JSON array helpers
 */
struct json_object *LUKS2_array_jobj(struct json_object *array, const char *num)
{
	struct json_object *jobj1;
	int i;

	for (i = 0; i < json_object_array_length(array); i++) {
		jobj1 = json_object_array_get_idx(array, i);
		if (!strcmp(num, json_object_get_string(jobj1)))
			return jobj1;
	}

	return NULL;
}

struct json_object *LUKS2_array_remove(struct json_object *array, const char *num)
{
	struct json_object *jobj1, *jobj_removing = NULL, *array_new;
	int i;

	jobj_removing = LUKS2_array_jobj(array, num);
	if (!jobj_removing)
		return NULL;

	/* Create new array without jobj_removing. */
	array_new = json_object_new_array();
	for (i = 0; i < json_object_array_length(array); i++) {
		jobj1 = json_object_array_get_idx(array, i);
		if (jobj1 != jobj_removing)
			json_object_array_add(array_new, json_object_get(jobj1));
	}

	return array_new;
}

/*
 * JSON struct access helpers
 */
json_object *LUKS2_get_keyslot_jobj(struct luks2_hdr *hdr, int keyslot)
{
	json_object *jobj1, *jobj2;
	char keyslot_name[16];

	if (!hdr)
		return NULL;

	if (snprintf(keyslot_name, sizeof(keyslot_name), "%u", keyslot) < 1)
		return NULL;

	if (!json_object_object_get_ex(hdr->jobj, "keyslots", &jobj1))
		return NULL;

	json_object_object_get_ex(jobj1, keyslot_name, &jobj2);
	return jobj2;
}

json_object *LUKS2_get_digest_jobj(struct luks2_hdr *hdr, int digest)
{
	json_object *jobj1, *jobj2;
	char digest_name[16];

	if (!hdr)
		return NULL;

	if (snprintf(digest_name, sizeof(digest_name), "%u", digest) < 1)
		return NULL;

	if (!json_object_object_get_ex(hdr->jobj, "digests", &jobj1))
		return NULL;

	json_object_object_get_ex(jobj1, digest_name, &jobj2);
	return jobj2;
}

json_object *LUKS2_get_area_jobj(struct luks2_hdr *hdr, int keyslot)
{
	json_object *jobj1, *jobj2, *jobj3;
	char keyslot_name[16];
	int i;

	if (!hdr)
		return NULL;

	if (snprintf(keyslot_name, sizeof(keyslot_name), "%u", keyslot) < 1)
		return NULL;

	json_object_object_get_ex(hdr->jobj, "areas", &jobj1);

	json_object_object_foreach(jobj1, key, val) {
		UNUSED(key);
		json_object_object_get_ex(val, "keyslots", &jobj2);
		for (i = 0; i < json_object_array_length(jobj2); i++) {
			jobj3 = json_object_array_get_idx(jobj2, i);
			if (!strcmp(keyslot_name, json_object_get_string(jobj3)))
				return val;
		}
	}
	return NULL;
}

json_object *LUKS2_get_segment_jobj(struct luks2_hdr *hdr, int segment)
{
	json_object *jobj1, *jobj2;
	char segment_name[16];

	if (!hdr)
		return NULL;

	if (snprintf(segment_name, sizeof(segment_name), "%u", segment) < 1)
		return NULL;

	if (!json_object_object_get_ex(hdr->jobj, "segments", &jobj1))
		return NULL;

	if (!json_object_object_get_ex(jobj1, segment_name, &jobj2))
		return NULL;

	return jobj2;
}

/*
 * json_type_int needs to be validated first.
 * See validate_json_uint32()
 */
uint32_t json_object_get_uint32(json_object *jobj)
{
	return json_object_get_int64(jobj);
}

/* jobj has to be json_type_string and numbered */
/* FIXME: sscanf() instead? */
static json_bool json_str_to_uint64(json_object *jobj, uint64_t *value)
{
	char *endptr;
	unsigned long long tmp;

	errno = 0;
	tmp = strtoull(json_object_get_string(jobj), &endptr, 10);
	if (*endptr || errno || tmp >= UINT64_MAX) {
		log_dbg("Failed to parse uint64_t type from string %s.",
			json_object_get_string(jobj));
		return FALSE;
	}

	*value = tmp;
	return TRUE;
}

uint64_t json_object_get_uint64(json_object *jobj)
{
	uint64_t r;
	return json_str_to_uint64(jobj, &r) ? r : 0;
}

/*
 * Validate helpers
 */
static json_bool numbered(const char *name, const char *key)
{
	int i;

	for (i = 0; key[i]; i++)
		if (!isdigit(key[i])) {
			log_dbg("%s \"%s\" is not in numbered form.", name, key);
			return FALSE;
		}
	return TRUE;
}

static json_object *contains(json_object *jobj, const char *name,
			     const char *section, const char *key, json_type type)
{
	json_object *sobj;

	if (!json_object_object_get_ex(jobj, key, &sobj) ||
	    !json_object_is_type(sobj, type)) {
		log_dbg("%s \"%s\" is missing \"%s\" (%s) specification.",
			section, name, key, json_type_to_name(type));
		return NULL;
	}

	return sobj;
}

/* use only on already validated 'segments' object */
static uint64_t get_first_data_offset(json_object *jobj_segs, const char *type)
{
	json_object *jobj_offset, *jobj_type;
	uint64_t tmp, min = UINT64_MAX;

	json_object_object_foreach(jobj_segs, key, val) {
		UNUSED(key);

		if (type) {
			json_object_object_get_ex(val, "type", &jobj_type);
			if (strcmp(type, json_object_get_string(jobj_type)))
				continue;
		}

		json_object_object_get_ex(val, "offset", &jobj_offset);
		tmp = json_object_get_uint64(jobj_offset);

		if (!tmp)
			return tmp;

		if (tmp < min)
			min = tmp;
	}

	return min;
}

static json_bool validate_json_uint32(json_object *jobj)
{
	int64_t tmp;

	errno = 0;
	tmp = json_object_get_int64(jobj);

	return (errno || tmp < 0 || tmp > UINT32_MAX) ? FALSE : TRUE;
}

static json_bool validate_keyslots_array(json_object *jarr, json_object *jobj_keys)
{
	json_object *jobj;
	int i = 0, length = json_object_array_length(jarr);

	while (i < length) {
		jobj = json_object_array_get_idx(jarr, i);
		if (!json_object_is_type(jobj, json_type_string)) {
			log_dbg("Illegal value type in keyslots array at index %d.", i);
			return FALSE;
		}

		if (!contains(jobj_keys, "", "Keyslots section", json_object_get_string(jobj), json_type_object))
			return FALSE;

		i++;
	}

	return TRUE;
}

static json_bool validate_intervals(int length, const struct interval *ix, uint64_t *data_offset)
{
	int j, i = 0;

	while (i < length) {
		if (ix[i].offset < 2 * LUKS2_HDR_16K_LEN) {
			log_dbg("Illegal area offset: %" PRIu64 ".", ix[i].offset);
			return FALSE;
		}

		if (!ix[i].length) {
			log_dbg("Area length must be greater than zero.");
			return FALSE;
		}

		/* first segment at offset 0 means we have detached header. Do not check then. */
		if (*data_offset && (ix[i].offset + ix[i].length) > *data_offset) {
			log_dbg("Area [%" PRIu64 ", %" PRIu64 "] intersects with segment starting at offset: %" PRIu64,
				ix[i].offset, ix[i].offset + ix[i].length, *data_offset);
			return FALSE;
		}

		for (j = 0; j < length; j++) {
			if (i == j)
				continue;
			if ((ix[i].offset >= ix[j].offset) && (ix[i].offset < (ix[j].offset + ix[j].length))) {
				log_dbg("Overlapping areas [%" PRIu64 ",%" PRIu64 "] and [%" PRIu64 ",%" PRIu64 "].",
					ix[i].offset, ix[i].offset + ix[i].length,
					ix[j].offset, ix[j].offset + ix[j].length);
				return FALSE;
			}
		}

		i++;
	}

	return TRUE;
}

int LUKS2_keyslot_validate(json_object *hdr_keyslot, const char *key)
{
	json_object *jobj_keylen;

	if (!contains(hdr_keyslot, key, "Keyslot", "type", json_type_string))
		return 1;
	if (!contains(hdr_keyslot, key, "Keyslot", "state", json_type_string))
		return 1;
	if (!(jobj_keylen = contains(hdr_keyslot, key, "Keyslot", "key_length", json_type_int)))
		return 1;

	/* enforce uint32_t type */
	if (!validate_json_uint32(jobj_keylen)) {
		log_dbg("Illegal field \"key_length\":%s.",
			json_object_get_string(jobj_keylen));
		return 1;
	}

	return 0;
}

int LUKS2_keyslot_is_type(json_object *jobj_keyslot, const char *type)
{
	json_object *jobj;

	if (!json_object_object_get_ex(jobj_keyslot, "type", &jobj) || !type)
		return 1;

	return strcmp(json_object_get_string(jobj), type);
}

static int hdr_validate_json_size(json_object *hdr_jobj, size_t max_size)
{
	return (strlen(json_object_to_json_string_ext(hdr_jobj, JSON_C_TO_STRING_PLAIN)) > max_size);
}

int LUKS2_check_json_size(const struct luks2_hdr *hdr)
{
	return hdr_validate_json_size(hdr->jobj, hdr->hdr_size - LUKS2_HDR_BIN_LEN);
}

static int hdr_validate_keyslots(json_object *hdr_jobj)
{
	json_object *jobj;

	if (!json_object_object_get_ex(hdr_jobj, "keyslots", &jobj)) {
		log_dbg("Missing keyslots section.");
		return 1;
	}

	json_object_object_foreach(jobj, key, val) {
		if (!numbered("Keyslot", key))
			return 1;
		if (LUKS2_keyslot_validate(val, key))
			return 1;
	}

	return 0;
}

static int hdr_validate_segments(json_object *hdr_jobj)
{
	json_object *jarr, *jobj, *jobj_keys, *jobj_offset, *jobj_ivoffset,
		    *jobj_length, *jobj_block;
	uint32_t block;
	uint64_t ivoffset, offset, length;

	if (!json_object_object_get_ex(hdr_jobj, "segments", &jobj)) {
		log_dbg("Missing segments section.");
		return 1;
	}

	if (json_object_object_length(jobj) < 1) {
		log_dbg("Empty segments section.");
		return 1;
	}

	/* keyslots should already be validated */
	if (!json_object_object_get_ex(hdr_jobj, "keyslots", &jobj_keys))
		return 1;

	json_object_object_foreach(jobj, key, val) {
		if (!numbered("Segment", key))
			return 1;

		if (!contains(val, key, "Segment", "type",     json_type_string) ||
		    !(jarr = contains(val, key, "Segment", "keyslots", json_type_array))  ||
		    !(jobj_offset = contains(val, key, "Segment", "offset", json_type_string)) ||
		    !(jobj_ivoffset = contains(val, key, "Segment", "iv_offset", json_type_string)) ||
		    !(jobj_length = contains(val, key, "Segment", "length", json_type_string)) ||
		    !contains(val, key, "Segment", "cipher",   json_type_string) ||
		    !(jobj_block = contains(val, key, "Segment", "block", json_type_int)))
			return 1;

		/* enforce uint32_t type */
		if (!validate_json_uint32(jobj_block)) {
			log_dbg("Illegal field \"block\":%s.",
				json_object_get_string(jobj_block));
			return 1;
		}

		block = json_object_get_uint32(jobj_block);
		if (!block || block % 512) {
			log_dbg("Illegal block field value: %" PRIu32, block);
			return 1;
		}

		if (!numbered("offset", json_object_get_string(jobj_offset)) ||
		    !numbered("iv_offset", json_object_get_string(jobj_ivoffset)))
			return 1;

		/* rule out values > UINT64_MAX */
		if (!json_str_to_uint64(jobj_offset, &offset) ||
		    !json_str_to_uint64(jobj_ivoffset, &ivoffset))
			return 1;

		if (offset % block) {
			log_dbg("Offset field has to be aligned to 'block' size: %" PRIu32,
				block);
			return 1;
		}

		if (ivoffset % block) {
			log_dbg("IV offset field has to be aligned to 'block' size: %" PRIu32,
				block);
			return 1;
		}

		/* length "dynamic" means whole device starting at 'offset' */
		if (strcmp(json_object_get_string(jobj_length), "dynamic")) {
			if (!numbered("length", json_object_get_string(jobj_length)) ||
			    !json_str_to_uint64(jobj_length, &length))
				return 1;

			if (length % block) {
				log_dbg("Length field has to be aligned to 'block' size: %" PRIu32,
					block);
				return 1;
			}
		}

		if (!validate_keyslots_array(jarr, jobj_keys))
			return 1;
	}

	return 0;
}

static int hdr_validate_areas(json_object *hdr_jobj)
{
	struct interval *intervals;
	json_object *jarr, *jobj, *jobj_keys, *jobj_offset, *jobj_length, *jobj_segs;
	int length, ret, i = 0;
	uint64_t first_offset;

	if (!json_object_object_get_ex(hdr_jobj, "areas", &jobj)) {
		log_dbg("Missing areas section.");
		return 1;
	}

	/* keyslots should already be validated */
	if (!json_object_object_get_ex(hdr_jobj, "keyslots", &jobj_keys))
		return 1;

	/* segments should already be validated */
	if (!json_object_object_get_ex(hdr_jobj, "segments", &jobj_segs))
		return 1;

	length = json_object_object_length(jobj);
	if (length <= 0) {
		log_dbg("Invalid areas specification.");
		return 1;
	}

	intervals = malloc(length * sizeof(*intervals));
	if (!intervals) {
		log_dbg("Not enough memory.");
		return -ENOMEM;
	}

	json_object_object_foreach(jobj, key, val) {
		if (!numbered("Area", key)) {
			free(intervals);
			return 1;
		}

		if (!(jarr = contains(val, key, "Area", "keyslots", json_type_array)) ||
		    !(jobj_offset = contains(val, key, "Area", "offset", json_type_string)) ||
		    !(jobj_length = contains(val, key, "Area", "length", json_type_string)) ||
		    !numbered("offset", json_object_get_string(jobj_offset)) ||
		    !numbered("length", json_object_get_string(jobj_length))) {
			free(intervals);
			return 1;
		}

		if (!validate_keyslots_array(jarr, jobj_keys)) {
			free(intervals);
			return 1;
		}

		/* rule out values > UINT64_MAX */
		if (!json_str_to_uint64(jobj_offset, &intervals[i].offset) ||
		    !json_str_to_uint64(jobj_length, &intervals[i].length)) {
			free(intervals);
			return 1;
		}

		i++;
	}

	if (length != i) {
		free(intervals);
		return 1;
	}

	first_offset = get_first_data_offset(jobj_segs, NULL);

	ret = validate_intervals(length, intervals, &first_offset) ? 0 : 1;

	free(intervals);

	return ret;
}

static int hdr_validate_digests(json_object *hdr_jobj)
{
	json_object *jarr, *jobj, *jobj_keys;

	if (!json_object_object_get_ex(hdr_jobj, "digests", &jobj)) {
		log_dbg("Missing digests section.");
		return 1;
	}

	/* keyslots should already be validated */
	if (!json_object_object_get_ex(hdr_jobj, "keyslots", &jobj_keys))
		return 1;

	json_object_object_foreach(jobj, key, val) {
		if (!numbered("Digest", key))
			return 1;

		if (!contains(val, key, "Digest", "type", json_type_string) ||
		    !(jarr = contains(val, key, "Digest", "keyslots", json_type_array)))
			return 1;

		if (!validate_keyslots_array(jarr, jobj_keys))
			return 1;
	}

	return 0;
}

static int hdr_validate_config(json_object *hdr_jobj)
{
	json_object *jobj;

	if (!json_object_object_get_ex(hdr_jobj, "config", &jobj)) {
		log_dbg("Missing config section.");
		return 1;
	}

	return 0;
}

int LUKS2_hdr_validate(json_object *hdr_jobj)
{
	struct {
		int (*validate)(json_object *);
	} checks[] = {
		{ hdr_validate_keyslots },
		{ hdr_validate_segments },
		{ hdr_validate_areas    },
		{ hdr_validate_digests  },
		{ hdr_validate_config   },
		{ NULL }
	};
	int i;

	if (!hdr_jobj)
		return 1;

	for (i = 0; checks[i].validate; i++)
		if (checks[i].validate && checks[i].validate(hdr_jobj))
			return 1;

	if (hdr_validate_json_size(hdr_jobj, LUKS2_HDR_16K_LEN - LUKS2_HDR_BIN_LEN)) {
		log_dbg("Json header is too large.");
		return 1;
	}

	return 0;
}

int LUKS2_hdr_read(struct crypt_device *cd, struct luks2_hdr *hdr)
{
	if (LUKS2_disk_hdr_read(cd, hdr, crypt_metadata_device(cd), 1))
		return -EINVAL;

	return 0;
}

int LUKS2_hdr_write(struct crypt_device *cd, struct luks2_hdr *hdr)
{
	if (LUKS2_hdr_validate(hdr->jobj))
		return -EINVAL;

	return LUKS2_disk_hdr_write(cd, hdr, crypt_metadata_device(cd));
}

int LUKS2_hdr_uuid(struct crypt_device *cd, struct luks2_hdr *hdr, const char *uuid)
{
	uuid_t partitionUuid;

	if (uuid && uuid_parse(uuid, partitionUuid) == -1) {
		log_err(cd, _("Wrong LUKS UUID format provided.\n"));
		return -EINVAL;
	}
	if (!uuid)
		uuid_generate(partitionUuid);

	uuid_unparse(partitionUuid, hdr->uuid);

	return LUKS2_disk_hdr_write(cd, hdr, crypt_metadata_device(cd));
}

void LUKS2_hdr_free(struct luks2_hdr *hdr)
{
	if (json_object_put(hdr->jobj))
		hdr->jobj = NULL;
	else
		log_dbg("LUKS2 header still in use?");
}

static uint64_t LUKS2_area_max_offset(struct luks2_hdr *hdr)
{
	json_object *jobj1, *jobj2;
	uint64_t max_offset = 0, length = 0, offset = 0;

	json_object_object_get_ex(hdr->jobj, "areas", &jobj1);

	json_object_object_foreach(jobj1, key, val) {
		UNUSED(key);
		json_object_object_get_ex(val, "offset", &jobj2);
		json_str_to_uint64(jobj2, &offset);
		json_object_object_get_ex(val, "length", &jobj2);
		json_str_to_uint64(jobj2, &length);
		if ((offset + length) > max_offset)
			max_offset = offset + length;
	}

	return max_offset;
}

int LUKS2_hdr_backup(struct crypt_device *cd, struct luks2_hdr *hdr,
		     const char *backup_file)
{
	struct device *device = crypt_metadata_device(cd);
	int r = 0, devfd = -1;
	ssize_t hdr_size;
	ssize_t buffer_size;
	char *buffer = NULL;

	r = LUKS2_hdr_read(cd, hdr);
	if (r)
		return r;

	hdr_size = LUKS2_area_max_offset(hdr);
	buffer_size = size_round_up(hdr_size, crypt_getpagesize());

	buffer = crypt_safe_alloc(buffer_size);
	if (!buffer)
		return -ENOMEM;

	log_dbg("Storing backup of header (%zu bytes) and keyslot area (%zu bytes).",
		LUKS2_HDR_BIN_LEN, hdr_size - 2 * LUKS2_HDR_BIN_LEN);

	log_dbg("Output backup file size: %zu bytes.", buffer_size);

	devfd = device_open(device, O_RDONLY);
	if(devfd == -1) {
		log_err(cd, _("Device %s is not a valid LUKS device.\n"), device_path(device));
		crypt_safe_free(buffer);
		return -EINVAL;
	}

	if (read_blockwise(devfd, device_block_size(device), buffer, hdr_size) < hdr_size) {
		close(devfd);
		crypt_safe_free(buffer);
		return -EIO;
	}
	close(devfd);

	devfd = open(backup_file, O_CREAT|O_EXCL|O_WRONLY, S_IRUSR);
	if (devfd == -1) {
		if (errno == EEXIST)
			log_err(cd, _("Requested header backup file %s already exists.\n"), backup_file);
		else
			log_err(cd, _("Cannot create header backup file %s.\n"), backup_file);
		close(devfd);
		crypt_safe_free(buffer);
		return -EINVAL;
	}
	if (write_buffer(devfd, buffer, buffer_size) < buffer_size) {
		log_err(cd, _("Cannot write header backup file %s.\n"), backup_file);
		r = -EIO;
	} else
		r = 0;

	close(devfd);
	crypt_safe_free(buffer);
	return r;
}

int LUKS2_hdr_restore(struct crypt_device *cd, struct luks2_hdr *hdr,
		     const char *backup_file)
{
	struct device *backup_device, *device = crypt_metadata_device(cd);
	int r, devfd = -1, diff_uuid = 0;
	ssize_t buffer_size = 0;
	char *buffer = NULL, msg[200];
	struct luks2_hdr hdr_file;

	r = device_alloc(&backup_device, backup_file);
	if (r < 0)
		return r;

	r = LUKS2_disk_hdr_read(cd, &hdr_file, backup_device, 0);
	device_free(backup_device);

	if (r < 0) {
		log_err(cd, _("Backup file doesn't contain valid LUKS header.\n"));
		return r;
	}

	buffer_size = LUKS2_area_max_offset(&hdr_file);
	buffer = crypt_safe_alloc(buffer_size);
	if (!buffer)
		return -ENOMEM;

	devfd = open(backup_file, O_RDONLY);
	if (devfd == -1) {
		log_err(cd, _("Cannot open header backup file %s.\n"), backup_file);
		crypt_safe_free(buffer);
		return -EINVAL;
	}

	if (read_buffer(devfd, buffer, buffer_size) < buffer_size) {
		log_err(cd, _("Cannot read header backup file %s.\n"), backup_file);
		close(devfd);
		crypt_safe_free(buffer);
		return -EIO;
	}
	close(devfd);

	LUKS2_hdr_free(hdr);
	r = LUKS2_hdr_read(cd, hdr);
	if (r == 0) {
		log_dbg("Device %s already contains LUKS header, checking UUID and offset.", device_path(device));
		if(buffer_size != (ssize_t)LUKS2_area_max_offset(hdr)) {
			log_err(cd, _("Data offset differ on device and backup, restore failed.\n"));
			crypt_safe_free(buffer);
			return -EINVAL;
		}
		if (memcmp(hdr->uuid, hdr_file.uuid, LUKS2_UUID_L))
			diff_uuid = 1;
	}

	if (snprintf(msg, sizeof(msg), _("Device %s %s%s"), device_path(device),
		 r ? _("does not contain LUKS header. Replacing header can destroy data on that device.") :
		     _("already contains LUKS header. Replacing header will destroy existing keyslots."),
		     diff_uuid ? _("\nWARNING: real device header has different UUID than backup!") : "") < 0) {
		crypt_safe_free(buffer);
		return -ENOMEM;
	}

	if (!crypt_confirm(cd, msg)) {
		crypt_safe_free(buffer);
		return -EINVAL;
	}

	log_dbg("Storing backup of header (%zu bytes) and keyslot area (%zu bytes) to device %s.",
		LUKS2_HDR_BIN_LEN, buffer_size - 2 * LUKS2_HDR_BIN_LEN, device_path(device));

	devfd = device_open(device, O_RDWR);
	if (devfd == -1) {
		if (errno == EACCES)
			log_err(cd, _("Cannot write to device %s, permission denied.\n"),
				device_path(device));
		else
			log_err(cd, _("Cannot open device %s.\n"), device_path(device));
		crypt_safe_free(buffer);
		return -EINVAL;
	}

	if (write_blockwise(devfd, device_block_size(device), buffer, buffer_size) < buffer_size)
		r = -EIO;
	else
		r = 0;
	crypt_safe_free(buffer);
	close(devfd);

	if (!r) {
		LUKS2_hdr_free(hdr);
		r = LUKS2_hdr_read(cd, hdr);
	}

	return r;
}

/*
 * Header dump
 */
static const char *get_priority_desc(json_object *jobj)
{
	crypt_keyslot_priority priority;
	json_object *jobj_priority;
	const char *text;

	if (json_object_object_get_ex(jobj, "priority", &jobj_priority))
		priority = (crypt_keyslot_priority)(int)json_object_get_int(jobj_priority);
	else
		priority = CRYPT_SLOT_PRIORITY_NORMAL;

	switch (priority) {
		case CRYPT_SLOT_PRIORITY_IGNORE: text = "ignored"; break;
		case CRYPT_SLOT_PRIORITY_PREFER: text = "preferred"; break;
		case CRYPT_SLOT_PRIORITY_NORMAL: text = "normal"; break;
		default: text = "invalid";
	}

	return text;
}

static void hdr_dump_keyslots(struct crypt_device *cd, json_object *hdr_jobj)
{
	json_object *keyslots_jobj, *areas_jobj, *digests_jobj, *jobj2, *jobj3, *jobj4;
	const char *tmps;
	int i;
	uint64_t value = 0;

	log_std(cd, "Keyslots:\n");
	json_object_object_get_ex(hdr_jobj, "keyslots", &keyslots_jobj);

	json_object_object_foreach(keyslots_jobj, slot, val) {
		json_object_object_get_ex(val, "type", &jobj2);
		tmps = json_object_get_string(jobj2);
		log_std(cd, "  %s: %s", slot, tmps);
		if (json_object_object_get_ex(val, "state", &jobj2))
			log_std(cd, " (%s)", json_object_get_string(jobj2));
		log_std(cd, "\n");

		if (json_object_object_get_ex(val, "key_length", &jobj2))
			log_std(cd, "\tKey:        %u bits\n", json_object_get_uint32(jobj2) * 8);

		log_std(cd, "\tPriority:   %s\n", get_priority_desc(val));

		LUKS2_keyslot_dump(cd, atoi(slot));

		json_object_object_get_ex(hdr_jobj, "areas", &areas_jobj);
		json_object_object_foreach(areas_jobj, key1, val1) {
			json_object_object_get_ex(val1, "keyslots", &jobj2);
			for (i = 0; i < json_object_array_length(jobj2); i++) {
				jobj3 = json_object_array_get_idx(jobj2, i);
				if (!strcmp(slot, json_object_get_string(jobj3))) {
					log_std(cd, "\tArea:       %s\n", key1);
					json_object_object_get_ex(val1, "offset", &jobj4);
					json_str_to_uint64(jobj4, &value);
					log_std(cd, "\t\tOffset: %" PRIu64 " [bytes]\n",
						value);
					json_object_object_get_ex(val1, "length", &jobj4);
					json_str_to_uint64(jobj4, &value);
					log_std(cd, "\t\tLength:  %" PRIu64 " [bytes]\n",
						value);
				}
			}
		}

		json_object_object_get_ex(hdr_jobj, "digests", &digests_jobj);
		json_object_object_foreach(digests_jobj, key2, val2) {
			json_object_object_get_ex(val2, "keyslots", &jobj2);
			for (i = 0; i < json_object_array_length(jobj2); i++) {
				jobj3 = json_object_array_get_idx(jobj2, i);
				if (!strcmp(slot, json_object_get_string(jobj3))) {
					log_std(cd, "\tDigest ID:  %s\n", key2);
				}
			}
		}
	}
}

static void hdr_dump_segments(struct crypt_device *cd, json_object *hdr_jobj)
{
	json_object *jobj1, *jobj2, *jobj3;
	uint64_t value;

	log_std(cd, "Data segments:\n");
	json_object_object_get_ex(hdr_jobj, "segments", &jobj1);

	json_object_object_foreach(jobj1, key, val) {
		json_object_object_get_ex(val, "type", &jobj2);
		log_std(cd, "  %s: %s\n", key, json_object_get_string(jobj2));

		json_object_object_get_ex(val, "offset", &jobj3);
		json_str_to_uint64(jobj3, &value);
		log_std(cd, "\toffset: %" PRIu64 " [bytes]\n", value);

		json_object_object_get_ex(val, "length", &jobj3);
		if (!(strcmp(json_object_get_string(jobj3), "dynamic")))
			log_std(cd, "\tlength: (whole device)\n");
		else {
			json_str_to_uint64(jobj3, &value);
			log_std(cd, "\tlength: %" PRIu64 " [bytes]\n", value);
		}

		json_object_object_get_ex(val, "cipher", &jobj3);
		log_std(cd, "\tcipher: %s\n", json_object_get_string(jobj3));

		json_object_object_get_ex(val, "block", &jobj3);
		log_std(cd, "\tblock:  %" PRIu32 " [bytes]\n", json_object_get_uint32(jobj3));

		log_std(cd, "\n");
	}
}

static void hdr_dump_digests(struct crypt_device *cd, json_object *hdr_jobj)
{
	json_object *jobj1, *jobj2;
	const char *tmps;

	log_std(cd, "Digests:\n");
	json_object_object_get_ex(hdr_jobj, "digests", &jobj1);

	json_object_object_foreach(jobj1, key, val) {
		json_object_object_get_ex(val, "type", &jobj2);
		tmps = json_object_get_string(jobj2);
		log_std(cd, "  %s: %s\n", key, tmps);

		LUKS2_digest_dump(cd, atoi(key));
	}
}

int LUKS2_hdr_dump(struct crypt_device *cd, struct luks2_hdr *hdr)
{
	if (!hdr->jobj)
		return -EINVAL;
	crypt_keyslot_destroy(cd,10);

	log_dbg("JSON: %s", json_object_to_json_string_ext(hdr->jobj, JSON_C_TO_STRING_PRETTY));

	log_std(cd, "LUKS header information\n");
	log_std(cd, "Version:       \t%u\n", hdr->version);
	log_std(cd, "Epoch:         \t%" PRIu64 "\n", hdr->seqid);
	log_std(cd, "Metadata area: \t%zu bytes\n", hdr->hdr_size - LUKS2_HDR_BIN_LEN);
	log_std(cd, "UUID:          \t%s\n", *hdr->uuid ? hdr->uuid : "(no UUID)");
	log_std(cd, "Label:         \t%s\n", *hdr->label ? hdr->label : "(no label)");
	log_std(cd, "Subsystem:     \t%s\n", *hdr->subsystem ? hdr->subsystem : "(no subsystem)");

	hdr_dump_segments(cd, hdr->jobj);
	hdr_dump_keyslots(cd, hdr->jobj);
	hdr_dump_digests(cd, hdr->jobj);

	return 0;
}

uint64_t LUKS2_get_data_offset(struct luks2_hdr *hdr)
{
	json_object *jobj1;

	if (!json_object_object_get_ex(hdr->jobj, "segments", &jobj1))
		return 0;

	return get_first_data_offset(jobj1, "crypt") / SECTOR_SIZE;
}

int LUKS2_activate(struct crypt_device *cd,
	const char *name,
	struct volume_key *vk,
	uint32_t flags)
{
	int r;
	enum devcheck device_check;
	struct crypt_dm_active_device dmd = {
		.target = DM_CRYPT,
		.uuid   = crypt_get_uuid(cd),
		.flags  = flags,
		.size   = 0,
		.data_device = crypt_data_device(cd),
		.u.crypt = {
			.vk     = vk,
			.offset = crypt_get_data_offset(cd),
			.cipher = crypt_get_cipher(cd),
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

	return dm_create_device(cd, name, CRYPT_LUKS2, &dmd, 0);
}

const char *LUKS2_get_cipher(struct luks2_hdr *hdr, unsigned int segment)
{
	json_object *jobj1, *jobj2, *jobj3;
	char buf[16];

	if (snprintf(buf, sizeof(buf), "%u", segment) < 1)
		return NULL;

	if (!json_object_object_get_ex(hdr->jobj, "segments", &jobj1))
		return 0;

	if (!json_object_object_get_ex(jobj1, buf, &jobj2))
		return 0;

	if (!json_object_object_get_ex(jobj2, "cipher", &jobj3))
		return 0;

	return json_object_get_string(jobj3);
}

static int LUKS2_keyslot_get_volume_key_size(struct luks2_hdr *hdr, const char *keyslot)
{
	json_object *jobj1, *jobj2, *jobj3;

	if (!json_object_object_get_ex(hdr->jobj, "keyslots", &jobj1))
		return 0;

	if (!json_object_object_get_ex(jobj1, keyslot, &jobj2))
		return 0;

	if (!json_object_object_get_ex(jobj2, "key_length", &jobj3))
		return 0;

	return json_object_get_int(jobj3);
}

int LUKS2_get_volume_key_size(struct luks2_hdr *hdr, unsigned int segment)
{
	json_object *jobj1, *jobj2, *jobj3, *jobj4;
	char buf[16];

	if (snprintf(buf, sizeof(buf), "%u", segment) < 1)
		return 0;

	/* Get segment keyslot section of the segment */
	if (!json_object_object_get_ex(hdr->jobj, "segments", &jobj1))
		return 0;

	if (!json_object_object_get_ex(jobj1, buf, &jobj2))
		return 0;

	if (!json_object_object_get_ex(jobj2, "keyslots", &jobj3))
		return 0;

	/* Get the first keyslot object */
	jobj4 = json_object_array_get_idx(jobj3, 0);
	if (!jobj4)
		return 0;

	return LUKS2_keyslot_get_volume_key_size(hdr, json_object_get_string(jobj4));
}
