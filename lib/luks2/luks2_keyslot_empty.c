/*
 * LUKS - Linux Unified Key Setup v2, empty keyslot handler
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

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <libcryptsetup.h>

static int empty_keyslot_open(struct crypt_device *cd,
	int keyslot,
	const char *password,
	size_t password_len,
	char *volume_key,
	size_t volume_key_len)
{
	return -EINVAL;
}

static int empty_keyslot_store(struct crypt_device *cd,
	int keyslot,
	const char *password,
	size_t password_len,
	const char *volume_key,
	size_t volume_key_len)
{
	return -EINVAL;
}

static int empty_keyslot_wipe(struct crypt_device *cd, int keyslot)
{
	return 0;
}

static int empty_keyslot_dump(struct crypt_device *cd, int keyslot)
{
	return 0;
}

static int empty_keyslot_validate(struct crypt_device *cd, int keyslot)
{
	return 0;
}

const keyslot_handler empty_keyslot = {
	.name  = "empty",
	.open  = empty_keyslot_open,
	.store = empty_keyslot_store,
	.wipe  = empty_keyslot_wipe,
	.dump  = empty_keyslot_dump,
	.validate  = empty_keyslot_validate,
};
