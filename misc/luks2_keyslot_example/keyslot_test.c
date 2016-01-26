/*
 * Example of LUKS2 kesylot handler (EXAMPLE)
 *
 * Copyright (C) 2016 Milan Broz <gmazyland@gmail.com>
 *
 * Use:
 *  - generate LUKS device useing master key
 *  - store master key file remotely
 *  - add new keyslot using this example
 *  - activate device with remote key using this example
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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <json-c/json.h>
#include <libssh/libssh.h> 
#include <libssh/sftp.h>
#include "libcryptsetup.h"

#define KEYSLOT_NUM 10

static json_object *get_jobj(struct crypt_device *cd, int keyslot)
{
	const char *json_slot;

	if (crypt_get_json(cd, CRYPT_JSON_KEYSLOT, KEYSLOT_NUM, &json_slot))
		return NULL;

	return json_tokener_parse(json_slot);
}

static int contains(json_object *jobj, const char *key, json_type type)
{
	json_object *sobj;

	if (!json_object_object_get_ex(jobj, key, &sobj) ||
	    !json_object_is_type(sobj, type))
		return 0;

	return 1;
}

static int read_remote_key(struct crypt_device *cd, const char *host,
			   const char *user, const char *path,
			   char *key, size_t key_len)
{
	ssh_session ssh = NULL;
	sftp_session sftp = NULL;
	sftp_file file = NULL;
	int r, port = 22;

	ssh = ssh_new();
	if (!ssh)
		return -EINVAL;

	ssh_options_set(ssh, SSH_OPTIONS_HOST, host);
	ssh_options_set(ssh, SSH_OPTIONS_USER, user);
	ssh_options_set(ssh, SSH_OPTIONS_PORT, &port);

	r = ssh_connect(ssh);
	if (r != SSH_OK) {
		crypt_log(cd, CRYPT_LOG_ERROR, "Connection failed: ");
		goto out;
	}

	r = ssh_is_server_known(ssh);
	if (r != SSH_SERVER_KNOWN_OK) {
		crypt_log(cd, CRYPT_LOG_ERROR, "Server not known: ");
		r = SSH_AUTH_ERROR;
		goto out;
	}

	r = ssh_userauth_publickey_auto(ssh, user, NULL);
	if (r != SSH_AUTH_SUCCESS) {
		crypt_log(cd, CRYPT_LOG_ERROR, "Public key authentication error: ");
		goto out;
	}

	sftp = sftp_new(ssh);
	if (!sftp) {
		crypt_log(cd, CRYPT_LOG_ERROR, "Cannot create sftp session: ");
		r = SSH_FX_FAILURE;
		goto out;
	}

	r = sftp_init(sftp);
	if (r != SSH_OK) {
		crypt_log(cd, CRYPT_LOG_ERROR, "Cannot init sftp session: ");
		goto out;
	}

	file = sftp_open(sftp, path, O_RDONLY, 0);
	if (!file) {
		crypt_log(cd, CRYPT_LOG_ERROR, "Cannot create sftp session: ");
		r = SSH_FX_FAILURE;
		goto out;
	}

	r = sftp_read(file, key, key_len);
	if (r < 0 || r != key_len) {
		crypt_log(cd, CRYPT_LOG_ERROR, "Cannot read remote key: ");
		r = SSH_FX_FAILURE;
		goto out;
	}
	r = SSH_OK;
out:
	if (r != SSH_OK) {
		crypt_log(cd, CRYPT_LOG_ERROR, ssh_get_error(ssh));
		crypt_log(cd, CRYPT_LOG_ERROR, "\n");
	}

	if (file)
		sftp_close(file);
	if (sftp)
		sftp_free(sftp);
	ssh_disconnect(ssh);
	ssh_free(ssh);
	return r == SSH_OK ? 0 : -EINVAL;
}

static int SSHTEST_keyslot_open(struct crypt_device *cd,
	int keyslot,
	const char *password __attribute__((unused)),
	size_t password_len __attribute__((unused)),
	char *volume_key,
	size_t volume_key_len)
{
	json_object *jobj_server, *jobj_user, *jobj_path, *jobj_keyslot;

	jobj_keyslot = get_jobj(cd, keyslot);
	json_object_object_get_ex(jobj_keyslot, "ssh_server", &jobj_server);
	json_object_object_get_ex(jobj_keyslot, "ssh_user",   &jobj_user);
	json_object_object_get_ex(jobj_keyslot, "ssh_path",   &jobj_path);

	return read_remote_key(cd, json_object_get_string(jobj_server),
				json_object_get_string(jobj_user),
				json_object_get_string(jobj_path),
				volume_key, volume_key_len);
}

static int SSHTEST_keyslot_store(struct crypt_device *cd,
	int keyslot,
	const char *password,
	size_t password_len,
	const char *volume_key,
	size_t volume_key_len)
{
	return -EINVAL;
}

static int SSHTEST_keyslot_wipe(struct crypt_device *cd, int keyslot)
{
	return 0;
}

static int SSHTEST_keyslot_dump(struct crypt_device *cd, int keyslot)
{
	json_object *jobj_server, *jobj_user, *jobj_path, *jobj_keyslot;
	char buf[4096];

	jobj_keyslot = get_jobj(cd, keyslot);
	json_object_object_get_ex(jobj_keyslot, "ssh_server", &jobj_server);
	json_object_object_get_ex(jobj_keyslot, "ssh_user",   &jobj_user);
	json_object_object_get_ex(jobj_keyslot, "ssh_path",   &jobj_path);

	snprintf(buf, sizeof(buf), "\tServer:%s\n\tUser:%s\n\tPath:%s\n",
		json_object_get_string(jobj_server),
		json_object_get_string(jobj_user),
		json_object_get_string(jobj_path));

	crypt_log(cd, CRYPT_LOG_NORMAL, buf);
	return 0;
}

static int SSHTEST_keyslot_validate(struct crypt_device *cd, int keyslot)
{
	json_object *jobj_keyslot = get_jobj(cd, keyslot);

	if (!jobj_keyslot)
		return -EINVAL;

	if (!contains(jobj_keyslot, "ssh_server", json_type_string) ||
	    !contains(jobj_keyslot, "ssh_user",   json_type_string) ||
	    !contains(jobj_keyslot, "ssh_path",   json_type_string))
		return -EINVAL;

	return 0;
}

const keyslot_handler SSHTEST_keyslot = {
	.name  = "sshkeytest",
	.open  = SSHTEST_keyslot_open,
	.store = SSHTEST_keyslot_store,
	.wipe  = SSHTEST_keyslot_wipe,
	.dump  = SSHTEST_keyslot_dump,
	.validate  = SSHTEST_keyslot_validate,
};

static int keyslot_add(const char *device, const char *server,
		   const char *user, const char *path)
{
	struct crypt_device *cd = NULL;
	json_object *jobj = NULL;
	int r;

	r = crypt_keyslot_register(&SSHTEST_keyslot);
	if (r < 0)
		return EXIT_FAILURE;

	r = crypt_init(&cd, device);
	if (r < 0)
		return EXIT_FAILURE;

	r = crypt_load(cd, CRYPT_LUKS2, NULL);
	if (r < 0) {
		crypt_free(cd);
		return EXIT_FAILURE;
	}

	jobj = json_object_new_object();
	json_object_object_add(jobj, "type", json_object_new_string(SSHTEST_keyslot.name));
	json_object_object_add(jobj, "state", json_object_new_string("active"));
	json_object_object_add(jobj, "key_length", json_object_new_int(crypt_get_volume_key_size(cd)));
	json_object_object_add(jobj, "priority", json_object_new_int(CRYPT_SLOT_PRIORITY_PREFER));

	/* our values */
	json_object_object_add(jobj, "ssh_server", json_object_new_string(server));
	json_object_object_add(jobj, "ssh_user", json_object_new_string(user));
	json_object_object_add(jobj, "ssh_path", json_object_new_string(path));

	r = crypt_keyslot_create(cd, KEYSLOT_NUM, SSHTEST_keyslot.name,
		json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_PLAIN));

	if (r == 0) {
		crypt_keyslot_assign_segment(cd, KEYSLOT_NUM, 0);
		crypt_keyslot_assign_digest(cd, KEYSLOT_NUM, 0);
	}

	crypt_free(cd);
	json_object_put(jobj);

	return EXIT_SUCCESS;
}

static int keyslot_open(const char *device, const char *name)
{
	struct crypt_device *cd = NULL;
	int r;

	r = crypt_keyslot_register(&SSHTEST_keyslot);
	if (r < 0)
		return EXIT_FAILURE;

	r = crypt_init(&cd, device);
	if (r < 0)
		return EXIT_FAILURE;

	r = crypt_load(cd, CRYPT_LUKS2, NULL);
	if (r < 0) {
		crypt_free(cd);
		return EXIT_FAILURE;
	}

	r = crypt_activate_by_passphrase(cd, name, KEYSLOT_NUM, "", 0, 0);

	crypt_free(cd);
	return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

static void keyslot_help(void)
{
	printf("Use parameters:\n add device server user path\n"
		" open device name\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	crypt_set_debug_level(CRYPT_LOG_DEBUG);

	/* Adding slot to device */
	if (argc == 6 && !strcmp("add", argv[1]))
		return keyslot_add(argv[2], argv[3], argv[4], argv[5]);

	/* Key check without activation */
	if (argc == 3 && !strcmp("open", argv[1]))
		return keyslot_open(argv[2], NULL);

	/* Key check with activation (requires root) */
	if (argc == 4 && !strcmp("open", argv[1]))
		return keyslot_open(argv[2], argv[3]);

	keyslot_help();
	return 1;
}
