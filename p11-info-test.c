/*
 * PKCS #11 Lite Test
 *
 * Copyright (c) 2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <stdlib.h>

#define CRYPTOKI_GNU  1

#include <p11-kit/p11-kit.h>
#include <p11-lite.h>

static struct ck_function_list **modules;

static const char *chomp (void *s, size_t len)
{
	char *p = s;

	for (; len > 0; --len)
		if (p[len - 1] == ' ')
			p[len - 1] = '\0';
		else
			break;

	return s;
}

struct flag_map {
	unsigned long flag;
	const char *name;
};

static void show_version (const char *prefix, const struct ck_version *v)
{
	if (v->major != 0 && v->minor != 0)
		printf ("%s: %u.%u", prefix, v->major, v->minor);
}

static void show_flags (const char *prefix, const struct flag_map *map,
			unsigned long flags)
{
	printf ("%s: ", prefix);

	for (; map->flag != 0; ++map)
		if ((flags & map->flag) != 0) {
			printf ("%s", map->name);

			if ((flags &= ~map->flag) != 0)
				printf (", ");
		}

	if (flags != 0)
		printf ("%08lx", flags);

	printf ("\n");
}

static
void show_counts (const char *prefix, unsigned long min, unsigned long max)
{
	if (min != CK_UNAVAILABLE_INFORMATION && max != CK_EFFECTIVELY_INFINITE)
		printf ("%s: %lu / %lu\n", prefix, min, max);
}

#ifndef CKM_GOSTR3410_KEY_PAIR_GEN
#define CKM_GOSTR3410_KEY_PAIR_GEN	0x1200
#define CKM_GOSTR3410			0x1201
#define CKM_GOSTR3411			0x1210
#endif

const char *p11_get_algo_name (unsigned long m)
{
	switch (m) {
	case CKM_RSA_PKCS_KEY_PAIR_GEN:	
	case CKM_RSA_PKCS:			return "RSA";
	case CKM_RSA_X_509:			return "RSA X.509";
	case CKM_MD5_RSA_PKCS:			return "MD5 + RSA";
	case CKM_SHA1_RSA_PKCS:			return "SHA1 + RSA";
	case CKM_RIPEMD160_RSA_PKCS:		return "RIPEMD160 + RSA";
	case CKM_DSA:				return "DSA";
	case CKM_DH_PKCS_KEY_PAIR_GEN:		return "DH key pair gen";
	case CKM_MD5:				return "MD5";
	case CKM_SHA_1:				return "SHA1";
	case CKM_RIPEMD128:			return "RIPEMD128";
	case CKM_RIPEMD160:			return "RIPEMD16";
	case CKM_SHA256:			return "SHA256";
	case CKM_SHA384:			return "SHA384";
	case CKM_SHA512:			return "SHA512";
	case CKM_SHA256_RSA_PKCS:		return "SHA256 + RSA";
	case CKM_SHA384_RSA_PKCS:		return "SHA384 + RSA";
	case CKM_SHA512_RSA_PKCS:		return "SHA512 + RSA";
	case CKM_GOSTR3410_KEY_PAIR_GEN:	return "GOSTR3410 key pair gen";
	case CKM_GOSTR3410:			return "GOSTR3410";
	case CKM_GOSTR3411:			return "GOSTR3411";
	}

	return NULL;
}

static struct flag_map algo_flags[] = {
	{CKF_HW,		"hw"},
	{CKF_ENCRYPT,		"encrypt"},
	{CKF_DECRYPT,		"decrypt"},
	{CKF_DIGEST,		"digest"},
	{CKF_SIGN,		"sign"},
	{CKF_SIGN_RECOVER,	"sign recover"},
	{CKF_VERIFY,		"verify"},
	{CKF_VERIFY_RECOVER,	"verify recover"},
	{CKF_GENERATE,		"generate"},
	{CKF_GENERATE_KEY_PAIR,	"generate key pair"},
	{CKF_WRAP,		"wrap"},
	{CKF_UNWRAP,		"unwrap"},
	{CKF_DERIVE,		"derive"},
	{CKF_EXTENSION,		"extension"},
	{}
};

static void show_algo (const struct ck_function_list *o, ck_slot_id_t slot,
		       ck_mechanism_type_t m)
{
	const char *name;
	ck_rv_t ret;
	struct ck_mechanism_info mi;

	if ((name = p11_get_algo_name (m)) == NULL)
		printf ("        algo %lx\n", m);
	else
		printf ("        algo %s\n", name);

	ret = p11_get_mechanism_info (o, slot, m, &mi);

	if (ret != CKR_OK) {
		printf ("            unavailable: %lx\n\n", ret);
		return;
	}

	show_counts ("            key size", mi.min_key_size, mi.max_key_size);
	show_flags ("            flags", algo_flags, mi.flags);
	printf ("\n");
}

static void show_algos (const struct ck_function_list *o, ck_slot_id_t slot)
{
	unsigned long count, i;
	ck_mechanism_type_t *m;

	if (p11_get_mechanism_list (o, slot, NULL, &count) != CKR_OK) {
		printf ("        algorithm list unavailable\n");
		return;
	}

	if ((m = malloc (sizeof (m[0]) * count)) == NULL) {
		perror ("E: cannot allocate algorithm list");
		return;
	}

	if (p11_get_mechanism_list (o, slot, m, &count) != CKR_OK) {
		printf ("        algorithm list unavailable\n");
		return;
	}

	for (i = 0; i < count; ++i)
		show_algo (o, slot, m[i]);

	free (m);
}

#ifndef CKF_ERROR_STATE
#define CKF_ERROR_STATE		0x01000000
#endif

static struct flag_map token_flags[] = {
	{CKF_RNG,				"rng"},
	{CKF_WRITE_PROTECTED,			"write protected"},
	{CKF_LOGIN_REQUIRED,			"login required"},
	{CKF_USER_PIN_INITIALIZED,		"pin initialized"},
	{CKF_RESTORE_KEY_NOT_NEEDED,		"keys saved"},
	{CKF_CLOCK_ON_TOKEN,			"clock"},
	{CKF_PROTECTED_AUTHENTICATION_PATH,	"protected auth path"},
	{CKF_DUAL_CRYPTO_OPERATIONS,		"dual ops"},
	{CKF_TOKEN_INITIALIZED,			"token initialized"},
	{CKF_SECONDARY_AUTHENTICATION,		"secondary auth"},
	{CKF_USER_PIN_COUNT_LOW,		"pin count low"},
	{CKF_USER_PIN_FINAL_TRY,		"pin final try"},
	{CKF_USER_PIN_LOCKED,			"pin locked"},
	{CKF_USER_PIN_TO_BE_CHANGED,		"pin need change"},
	{CKF_SO_PIN_COUNT_LOW,			"so pin count low"},
	{CKF_SO_PIN_FINAL_TRY,			"so pin final try"},
	{CKF_SO_PIN_LOCKED,			"so pin locked"},
	{CKF_SO_PIN_TO_BE_CHANGED,		"so pin need change"},
	{CKF_ERROR_STATE,			"error"},
	{}
};

static void token_info (const struct ck_function_list *o, ck_slot_id_t slot)
{
	struct ck_token_info ti;

	if (p11_get_token_info (o, slot, &ti) != CKR_OK) {
		printf ("        token unavailable\n");
		return;
	}

	printf ("        label: %.32s\n",  chomp (ti.label, 32));
	printf ("        vendor: %.32s\n", chomp (ti.manufacturer_id, 32));
	printf ("        model: %.16s\n",  chomp (ti.model, 16));
	printf ("        serial: %.16s\n", chomp (ti.serial_number, 16));
	show_flags ("        flags", token_flags, ti.flags);

	show_counts ("        session count",
		     ti.session_count, ti.max_session_count);

	show_counts ("        rw session count",
		     ti.rw_session_count, ti.max_rw_session_count);

	show_counts ("        pin size", ti.min_pin_len, ti.max_pin_len);

	show_counts ("        public mem",
		     ti.free_public_memory, ti.total_public_memory);

	show_counts ("        private mem",
		     ti.free_private_memory, ti.total_private_memory);

	show_version ("        token hw", &ti.hardware_version);
	show_version ("        token fw", &ti.firmware_version);

	if ((ti.flags & CKF_CLOCK_ON_TOKEN) != 0)
		printf ("        time: %.16s", ti.utc_time);

	printf ("\n");
	show_algos (o, slot);
}

static struct flag_map slot_flags[] = {
	{CKF_TOKEN_PRESENT,	"token present"},
	{CKF_REMOVABLE_DEVICE,	"removable"},
	{CKF_HW_SLOT,		"hw"},
	{}
};

static void slot_info (const struct ck_function_list *o, ck_slot_id_t slot)
{
	struct ck_slot_info  si;

	printf ("    slot %lu\n", slot);

	if (p11_get_slot_info (o, slot, &si) != CKR_OK) {
		printf ("        unavailable\n\n");
		return;
	}
#if 0
	printf ("        vendor: %.32s\n",
		chomp (si.manufacturer_id, 32));

	printf ("        description: %.64s\n",
		chomp (si.slot_description, 64));
#endif
	show_version ("        stol hw", &si.hardware_version);
	show_version ("        slot fw", &si.firmware_version);
	show_flags ("        flags", slot_flags, si.flags);

	printf ("\n");

	if ((si.flags & CKF_TOKEN_PRESENT) != 0)
		token_info (o, slot);
}

static void module_info (struct ck_function_list *o)
{
	const struct ck_version *version;
	struct ck_info info;

	ck_slot_id_t *s;
	unsigned long count, i;

	printf ("Module %s\n", p11_kit_module_get_name (o));
	version = p11_get_version (o);
	printf ("    API version %u.%u\n", version->major, version->minor);

	if (version->major != 2)
		return;

	if (p11_get_info (o, &info) != CKR_OK) {
		printf ("    unavailable\n\n");
		return;
	}

	printf ("    vendor: %.32s\n", chomp (info.manufacturer_id, 32));
	printf ("    description: %.32s\n", chomp (info.library_description,
						   32));
	printf ("    version %u.%u\n", info.library_version.major,
				       info.library_version.minor);

	printf ("\n");

	if (p11_get_slot_list (o, false, NULL, &count) != CKR_OK)
		return;

	if ((s = malloc (sizeof (s[0]) * count)) == NULL) {
		perror ("E: cannot allocate slots");
		return;
	}

	if (p11_get_slot_list (o, false, s, &count) != CKR_OK) {
		fprintf (stderr, "E: cannot get slot list\n");
		free (s);
		return;
	}

	for (i = 0; i < count; ++i)
		slot_info (o, s[i]);

	free (s);
}

int main (int argc, char *argv[])
{
	struct ck_function_list **p;

	if ((modules = p11_kit_modules_load_and_initialize (0)) == NULL) {
		fprintf (stderr, "E: cannot load modules: %s",
			 p11_kit_message ());
		return 1;
	}

	for (p = modules; *p != NULL; ++p)
		module_info (*p);

	p11_kit_modules_finalize_and_release (modules);
	return 0;
}
