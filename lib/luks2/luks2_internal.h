/*
 * LUKS - Linux Unified Key Setup v2
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

#ifndef _CRYPTSETUP_LUKS2_INTERNAL_H
#define _CRYPTSETUP_LUKS2_INTERNAL_H

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <json-c/json.h>

#include "internal.h"
#include "base64.h"
#include "luks2.h"

#define UNUSED(x) (void)(x)

/*
 * On-disk access function prototypes
 */
int LUKS2_disk_hdr_read(struct crypt_device *cd, struct luks2_hdr *hdr,
			struct device *device, int do_recovery);
int LUKS2_disk_hdr_write(struct crypt_device *cd, struct luks2_hdr *hdr,
			 struct device *device);

/*
 * JSON struct access helpers
 */
json_object *LUKS2_get_keyslot_jobj(struct luks2_hdr *hdr, int keyslot);
json_object *LUKS2_get_digest_jobj(struct luks2_hdr *hdr, int keyslot);
json_object *LUKS2_get_area_jobj(struct luks2_hdr *hdr, int keyslot);
json_object *LUKS2_get_segment_jobj(struct luks2_hdr *hdr, int segment);

/*
 * LUKS2 JSON validation
 */

int LUKS2_hdr_validate(json_object *hdr_jobj);
int LUKS2_keyslot_validate(json_object *jobj_keyslot, const char *key);
int LUKS2_keyslot_is_type(json_object *jobj_keyslot, const char *type);
int LUKS2_check_json_size(const struct luks2_hdr *hdr);

/*
 * JSON array helpers
 */
struct json_object *LUKS2_array_jobj(struct json_object *array, const char *num);
struct json_object *LUKS2_array_remove(struct json_object *array, const char *num);

#endif
