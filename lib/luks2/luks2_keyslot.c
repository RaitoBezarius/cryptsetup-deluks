/*
 * LUKS - Linux Unified Key Setup v2, keyslot handling
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

/* Internal implementations */
extern const keyslot_handler luks2_keyslot;
extern const keyslot_handler empty_keyslot;

static const keyslot_handler *keyslot_handlers[LUKS2_KEYSLOTS_MAX] = {
	&luks2_keyslot,
	&empty_keyslot,
	NULL
};

int crypt_keyslot_register(const keyslot_handler *handler)
{
	int i;

	for (i = 0; i < LUKS2_KEYSLOTS_MAX && keyslot_handlers[i]; i++) {
		if (!strcmp(keyslot_handlers[i]->name, handler->name)) {
			log_dbg("Keyslot handler %s is already registered.", handler->name);
			return -EINVAL;
		}
	}

	if (i == LUKS2_KEYSLOTS_MAX) {
		log_dbg("No more space for another keyslot handler.");
		return -EINVAL;
	}

	keyslot_handlers[i] = handler;
	return 0;
}

static const keyslot_handler
*LUKS2_keyslot_handler_type(struct crypt_device *cd, const char *type)
{
	int i;

	for (i = 0; i < LUKS2_KEYSLOTS_MAX && keyslot_handlers[i]; i++) {
		if (!strcmp(keyslot_handlers[i]->name, type))
			return keyslot_handlers[i];
	}

	return NULL;
}

static const keyslot_handler
*LUKS2_keyslot_handler(struct crypt_device *cd, int keyslot)
{
	struct luks2_hdr *hdr;
	json_object *jobj1, *jobj2;

	if (keyslot < 0)
		return NULL;

	if (!(hdr = crypt_get_hdr(cd, CRYPT_LUKS2)))
		return NULL;

	if (!(jobj1 = LUKS2_get_keyslot_jobj(hdr, keyslot)))
		return NULL;

	if (!json_object_object_get_ex(jobj1, "type", &jobj2))
		return NULL;

	return LUKS2_keyslot_handler_type(cd, json_object_get_string(jobj2));
}

static crypt_keyslot_info LUKS2_keyslot_active(struct luks2_hdr *hdr, int keyslot)
{
	json_object *jobj1, *jobj2;

	if (keyslot >= LUKS2_KEYSLOTS_MAX)
		return CRYPT_SLOT_INVALID;

	jobj1 = LUKS2_get_keyslot_jobj(hdr, keyslot);
	if (!json_object_object_get_ex(jobj1, "state", &jobj2))
		return CRYPT_SLOT_INACTIVE;

	if (!strcmp(json_object_get_string(jobj2), "inactive"))
		return CRYPT_SLOT_INACTIVE;
	else if (!strcmp(json_object_get_string(jobj2), "active"))
		return CRYPT_SLOT_ACTIVE;

	return CRYPT_SLOT_INVALID;
}

static int LUKS2_keyslot_find_free(struct luks2_hdr *hdr)
{
	int i;

	for (i = 0; i < LUKS2_KEYSLOTS_MAX; i++)
		if (!LUKS2_get_keyslot_jobj(hdr, i))
			return i;

	return -EINVAL;
}

int LUKS2_keyslot_find_empty(struct luks2_hdr *hdr, const char *type)
{
	json_object *keyslots_jobj, *jobj;

	json_object_object_get_ex(hdr->jobj, "keyslots", &keyslots_jobj);
	json_object_object_foreach(keyslots_jobj, slot, val) {
		json_object_object_get_ex(val, "type", &jobj);
		if (strcmp(type, json_object_get_string(jobj)))
			continue;

		if (json_object_object_get_ex(val, "state", &jobj) &&
			!strcmp("inactive", json_object_get_string(jobj)))
			return atoi(slot);
	}

	return LUKS2_keyslot_find_free(hdr);
}

int LUKS2_keyslot_active_count(struct luks2_hdr *hdr)
{
	int num = 0;
	json_object *keyslots_jobj, *jobj;

	json_object_object_get_ex(hdr->jobj, "keyslots", &keyslots_jobj);
	json_object_object_foreach(keyslots_jobj, slot, val) {
		UNUSED(slot);
		if (json_object_object_get_ex(val, "state", &jobj) &&
			!strcmp("active", json_object_get_string(jobj)))
			num++;
	}

	return num;
}

crypt_keyslot_info LUKS2_keyslot_info(struct luks2_hdr *hdr, int keyslot)
{
	crypt_keyslot_info ki;

	if(keyslot >= LUKS2_KEYSLOTS_MAX || keyslot < 0)
		return CRYPT_SLOT_INVALID;

	ki = LUKS2_keyslot_active(hdr, keyslot);
	if (ki != CRYPT_SLOT_ACTIVE)
		return ki;

	if (LUKS2_keyslot_active_count(hdr) == 1)
		return CRYPT_SLOT_ACTIVE_LAST;

	return CRYPT_SLOT_ACTIVE;
}

int LUKS2_keyslot_area(struct luks2_hdr *hdr,
	int keyslot,
	uint64_t *offset,
	uint64_t *length)
{
	json_object *jobj_area, *jobj;

	if(LUKS2_keyslot_info(hdr, keyslot) == CRYPT_SLOT_INVALID)
		return -EINVAL;

	jobj_area = LUKS2_get_area_jobj(hdr, keyslot);
	if (!jobj_area)
		return -ENOENT;

	if (!json_object_object_get_ex(jobj_area, "offset", &jobj))
		return -EINVAL;
	*offset = json_object_get_int64(jobj);

	if (!json_object_object_get_ex(jobj_area, "length", &jobj))
		return -EINVAL;
	*length = json_object_get_int64(jobj);

	return 0;
}

int LUKS2_keyslot_create(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	const char *type,
	const char *json,
	int commit)
{
	const keyslot_handler *h;
	json_object *jobj_keyslot, *jobj_keyslots, *jobj;
	enum json_tokener_error jerr;
	char buf[4096], num[16];
	const char *json_buf;
	int r;

	if (!(h = LUKS2_keyslot_handler_type(cd, type)))
		return -EINVAL;

	if (keyslot == CRYPT_ANY_SLOT)
		keyslot = LUKS2_keyslot_find_empty(hdr, type);

	if (keyslot < 0 || keyslot > LUKS2_KEYSLOTS_MAX)
		return -ENOMEM;

	/* Allow to modify only non-existent or inactive slot */
	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, keyslot);
	if (jobj_keyslot && json_object_object_get_ex(jobj_keyslot, "state", &jobj) &&
	    !strcmp("active", json_object_get_string(jobj))) {
		log_dbg("Cannot modify already active keyslot %d.", keyslot);
		return -EINVAL;
	}

	if (!json_object_object_get_ex(hdr->jobj, "keyslots", &jobj_keyslots))
		return -EINVAL;

	if (json) {
		json_buf = json;
	} else {
		snprintf(buf, sizeof(buf),
			 "{\"type\":\"%s\",\"state\":\"inactive\",\"key_length\":%u}",
			 type, crypt_get_volume_key_size(cd));
		json_buf = buf;
	}

	jobj = json_tokener_parse_verbose(json_buf, &jerr);
	if (!jobj) {
		log_dbg("Keyslot JSON parse failed.");
		return -EINVAL;
	}

	snprintf(num, sizeof(num), "%d", keyslot);

	if (LUKS2_keyslot_validate(jobj, num)) {
		json_object_put(jobj);
		return -EINVAL;
	}

	if (LUKS2_keyslot_is_type(jobj, h->name)) {
		log_dbg("Keyslot object doesn't match requested handler type: %s.",
			h->name);
		json_object_put(jobj);
		return -EINVAL;
	}

	json_object_object_add(jobj_keyslots, num, jobj);
	if (LUKS2_check_json_size(hdr)) {
		log_dbg("New keyslot too large to fit in free metadata space.");
		json_object_object_del(jobj_keyslots, num);
		return -ENOSPC;
	}

	// FIXME: validate optional priority field
	r = h->validate(cd, keyslot);
	if (r < 0) {
		log_dbg("Keyslot validation failed.");
		json_object_object_del(jobj_keyslots, num);
		return r;
	}

	return commit ? LUKS2_hdr_write(cd, hdr) : 0;
}

static int LUKS2_open_and_verify(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	const char *password,
	size_t password_len,
	struct volume_key *vk)
{
	const keyslot_handler *h;
	int r;

	if (!(h = LUKS2_keyslot_handler(cd, keyslot)))
		return -ENOENT;

	r = h->open(cd, keyslot, password, password_len, vk->key, vk->keylength);
	if (r < 0) {
		log_dbg("Keyslot %d (%s) open failed with %d.", keyslot, h->name, r);
		return r;
	}

	r = LUKS2_digest_verify(cd, hdr, vk, keyslot);
	if (r < 0)
		return r;

	return keyslot;
}

static int LUKS2_keyslot_open_priority(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	crypt_keyslot_priority priority,
	const char *password,
	size_t password_len,
	struct volume_key **vk)
{
	json_object *keyslots_jobj, *jobj;
	crypt_keyslot_priority slot_priority;
	int r = -ENOENT, keyslot;

	json_object_object_get_ex(hdr->jobj, "keyslots", &keyslots_jobj);

	json_object_object_foreach(keyslots_jobj, slot, val) {

		/* Skip inactive */
		if (!json_object_object_get_ex(val, "state", &jobj))
			continue;
		if (strcmp("active", json_object_get_string(jobj)))
			continue;

		if (!json_object_object_get_ex(val, "priority", &jobj))
			slot_priority = CRYPT_SLOT_PRIORITY_NORMAL;
		else
			slot_priority = json_object_get_int(jobj);

		keyslot = atoi(slot);
		if (slot_priority != priority) {
			log_dbg("Keyslot %d priority %d != %d (required), skipped.",
				keyslot, slot_priority, priority);
			continue;
		}

		r = LUKS2_open_and_verify(cd, hdr, keyslot, password, password_len, *vk);

		/* Do not retry for errors that are no -EPERM or -ENOENT,
		   former meaning password wrong, latter key slot inactive */
		if ((r != -EPERM) && (r != -ENOENT))
			break;
	}

	return r;
}

int LUKS2_keyslot_open(struct crypt_device *cd,
	int keyslot,
	const char *password,
	size_t password_len,
	struct volume_key **vk)
{
	struct luks2_hdr *hdr;
	int r_prio, r = -EINVAL;

	*vk = crypt_alloc_volume_key(crypt_get_volume_key_size(cd), NULL);
	if (!*vk)
		return -ENOMEM;

	hdr = crypt_get_hdr(cd, CRYPT_LUKS2);

	if (keyslot == CRYPT_ANY_SLOT) {
		r_prio = LUKS2_keyslot_open_priority(cd, hdr, CRYPT_SLOT_PRIORITY_PREFER,
			password, password_len, vk);
		if (r_prio >= 0)
			r = r_prio;
		else if (r_prio < 0 && (r_prio != -EPERM) && (r_prio != -ENOENT))
			r = r_prio;
		else
			r = LUKS2_keyslot_open_priority(cd, hdr, CRYPT_SLOT_PRIORITY_NORMAL,
				password, password_len, vk);
		/* Prefer password wrong to no entry from priority slot */
		if (r_prio == -EPERM && r == -ENOENT)
			r = r_prio;
	} else
		r = LUKS2_open_and_verify(cd, hdr, keyslot, password, password_len, *vk);

	if (r < 0) {
		crypt_free_volume_key(*vk);
		*vk = NULL;
	}

	return r;
}

int LUKS2_keyslot_store(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	const char *password,
	size_t password_len,
	const struct volume_key *vk)
{
	const keyslot_handler *h;
	int r;

	if (keyslot == CRYPT_ANY_SLOT)
		return -EINVAL;

	if (!(h = LUKS2_keyslot_handler(cd, keyslot)))
		return -EINVAL;

	/* Replace empty keyslot with luks2 here, old API compatibility. */
	if (!strcmp(h->name, "empty")) {
		r = LUKS2_keyslot_luks2_format(cd, hdr, keyslot,
				crypt_get_cipher_segment(cd, 0),
				crypt_get_volume_key_size(cd));
		if (r < 0)
			return r;

		h = LUKS2_keyslot_handler(cd, keyslot);
		if (!h)
			return -EINVAL;
	}

	return h->store(cd, keyslot, password, password_len,
			vk->key, vk->keylength);
}

int LUKS2_keyslot_wipe(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot)
{
	struct device *device = crypt_metadata_device(cd);
	uint64_t area_offset, area_length;
	int area_exists = 0, r;
	char num[16];
	json_object *jobj_keyslot, *keyslots_jobj;
	const keyslot_handler *h;

	h = LUKS2_keyslot_handler(cd, keyslot);

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, keyslot);
	if (!jobj_keyslot)
		return -EINVAL;

	/* secure deletion of possible key material in keyslot area */
	r = crypt_keyslot_area(cd, keyslot, &area_offset, &area_length);
	if (r == 0) {
		r = crypt_wipe(device, area_offset, area_length, CRYPT_WIPE_DISK, 0);
		if (r) {
			if (r == -EACCES) {
				log_err(cd, _("Cannot write to device %s, permission denied.\n"),
					device_path(device));
				r = -EINVAL;
			} else
				log_err(cd, _("Cannot wipe device %s.\n"),
					device_path(device));
			return r;
		}
		area_exists = 1;
	} else if (r != -ENOENT)
		return r;

	/* Slot specific wipe */
	if (h) {
		r = h->wipe(cd, keyslot);
		if (r < 0)
			return r;
	} else
		log_dbg("Wiping keyslot %d without specific-slot handler loaded.", keyslot);

	if (area_exists) {
		/* Do not remove slot info if area exists, just wipe keyslot info. */
		json_object_object_add(jobj_keyslot, "state", json_object_new_string("inactive"));

		/* Wipe all JSON data if we have no handler loaded. */
		if (!h) {
			r = LUKS2_keyslot_create(cd, hdr, keyslot, "empty", NULL, 0);
			if (r < 0)
				return r;
		}
	} else {
		r = LUKS2_keyslot_assign(cd, hdr, keyslot, CRYPT_ANY_SEGMENT, 0, 0);
		if (r < 0)
			return r;
		r = LUKS2_digest_assign(cd, hdr, keyslot, CRYPT_ANY_DIGEST, 0, 0);
		if (r < 0)
			return r;

		/* Remove slot from JSON */
		json_object_object_get_ex(hdr->jobj, "keyslots", &keyslots_jobj);
		snprintf(num, sizeof(num), "%d", keyslot);
		json_object_object_del(keyslots_jobj, num);
	}

	return LUKS2_hdr_write(cd, hdr);
}

int LUKS2_keyslot_dump(struct crypt_device *cd, int keyslot)
{
	const keyslot_handler *h;

	if (!(h = LUKS2_keyslot_handler(cd, keyslot)))
		return -EINVAL;

	return h->dump(cd, keyslot);
}

int LUKS2_keyslot_json_get(struct crypt_device *cd, struct luks2_hdr *hdr,
			   int keyslot, const char **json)
{
	json_object *jobj_keyslot;

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, keyslot);
	if (!jobj_keyslot)
		return -EINVAL;

	*json = json_object_to_json_string_ext(jobj_keyslot, JSON_C_TO_STRING_PLAIN);
	return 0;
}

static int assign_one_segment(struct crypt_device *cd, struct luks2_hdr *hdr,
			      int keyslot, int segment, int assign)
{
	json_object *jobj1, *jobj_segment, *jobj_segment_keyslots;
	char num[16];

	log_dbg("Keyslot %i %s segment %i.", keyslot, assign ? "assigned to" : "unassigned from", segment);

	jobj_segment = LUKS2_get_segment_jobj(hdr, segment);
	if (!jobj_segment)
		return -EINVAL;

	json_object_object_get_ex(jobj_segment, "keyslots", &jobj_segment_keyslots);
	if (!jobj_segment_keyslots)
		return -EINVAL;

	snprintf(num, sizeof(num), "%d", keyslot);
	if (assign) {
		jobj1 = LUKS2_array_jobj(jobj_segment_keyslots, num);
		if (!jobj1)
			json_object_array_add(jobj_segment_keyslots, json_object_new_string(num));
	} else {
		jobj1 = LUKS2_array_remove(jobj_segment_keyslots, num);
		if (jobj1)
			json_object_object_add(jobj_segment, "keyslots", jobj1);
	}

	return 0;
}

int LUKS2_keyslot_assign(struct crypt_device *cd, struct luks2_hdr *hdr,
			 int keyslot, int segment, int assign, int commit)
{
	json_object *jobj_segments;
	int r = 0;

	if (!LUKS2_get_keyslot_jobj(hdr, keyslot))
		return -EINVAL;

	if (segment == CRYPT_ANY_SEGMENT) {
		json_object_object_get_ex(hdr->jobj, "segments", &jobj_segments);

		json_object_object_foreach(jobj_segments, key, val) {
			UNUSED(val);
			r = assign_one_segment(cd, hdr, keyslot, atoi(key), assign);
			if (r < 0)
				break;
		}
	} else
		r = assign_one_segment(cd, hdr, keyslot, segment, assign);

	if (r < 0)
		return r;

	// FIXME: do not write header in nothing changed
	return commit ? LUKS2_hdr_write(cd, hdr) : 0;
}

crypt_keyslot_priority LUKS2_keyslot_priority_get(struct crypt_device *cd,
	  struct luks2_hdr *hdr, int keyslot)
{
	json_object *jobj_keyslot, *jobj_priority;

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, keyslot);
	if (!jobj_keyslot)
		return CRYPT_SLOT_PRIORITY_INVALID;

	if (!json_object_object_get_ex(jobj_keyslot, "priority", &jobj_priority))
		return CRYPT_SLOT_PRIORITY_NORMAL;

	return json_object_get_int(jobj_priority);
}

int LUKS2_keyslot_priority_set(struct crypt_device *cd, struct luks2_hdr *hdr,
			       int keyslot, crypt_keyslot_priority priority, int commit)
{
	json_object *jobj_keyslot;

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, keyslot);
	if (!jobj_keyslot)
		return -EINVAL;

	if (priority == CRYPT_SLOT_PRIORITY_NORMAL)
		json_object_object_del(jobj_keyslot, "priority");
	else
		json_object_object_add(jobj_keyslot, "priority", json_object_new_int(priority));

	return commit ? LUKS2_hdr_write(cd, hdr) : 0;
}
