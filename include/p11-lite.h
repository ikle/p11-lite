/*
 * PKCS #11 Lite API
 *
 * Copyright (c) 2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef P11_LITE_H
#define P11_LITE_H  1

#include <stddef.h>
#include <stdbool.h>

#define CRYPTOKI_GNU  1

#include <p11-kit/pkcs11.h>

#define P11_LITE_DEFINE(name, ...) \
static inline ck_rv_t p11_##name (struct ck_function_list *o, __VA_ARGS__)

#define P11_LITE_DEFINE_S(name, ...)					\
static inline ck_rv_t							\
p11_##name (struct ck_function_list *o, ck_session_handle_t session,	\
	    __VA_ARGS__)

/* General purpose functions */

static inline
const struct ck_version *p11_get_version (struct ck_function_list *o)
{
	return &o->version;
}

P11_LITE_DEFINE (get_info, struct ck_info *info)
{
	return o->C_GetInfo (info);
}

/* Slot and token management functions */

P11_LITE_DEFINE (get_slot_list, bool token_present,
		 ck_slot_id_t *slot_list, unsigned long *count)
{
	return o->C_GetSlotList (token_present, slot_list, count);
}

P11_LITE_DEFINE (get_slot_info, ck_slot_id_t slot,
		 struct ck_slot_info *info)
{
	return o->C_GetSlotInfo (slot, info);
}

P11_LITE_DEFINE (get_token_info, ck_slot_id_t slot,
		 struct ck_token_info *info)
{
	return o->C_GetTokenInfo (slot, info);
}

P11_LITE_DEFINE (wait_for_slot_event, ck_flags_t flags, ck_slot_id_t *slot,
		 void *reserved)
{
	return o->C_WaitForSlotEvent (flags, slot, reserved);
}

P11_LITE_DEFINE (get_mechanism_list, ck_slot_id_t slot,
		 ck_mechanism_type_t *mechanism_list, unsigned long *count)
{
	return o->C_GetMechanismList (slot, mechanism_list, count);
}

P11_LITE_DEFINE (get_mechanism_info, ck_slot_id_t slot,
		 ck_mechanism_type_t type, struct ck_mechanism_info *info)
{
	return o->C_GetMechanismInfo (slot, type, info);
}

P11_LITE_DEFINE (init_token, ck_slot_id_t slot, const char *pin,
		 size_t pin_len, const char *label)
{
	return o->C_InitToken (slot, (void *) pin, pin_len, (void *) label);
}

P11_LITE_DEFINE_S (init_pin, const char *pin, size_t pin_len)
{
	return o->C_InitPIN (session, (void *) pin, pin_len);
}

P11_LITE_DEFINE_S (set_pin, const char *old_pin, size_t old_len,
		   const char *new_pin, size_t new_len)
{
	return o->C_SetPIN (session, (void *) old_pin, old_len,
			    (void *) new_pin, new_len);
}

/* Session management functions */

P11_LITE_DEFINE (open_session, ck_slot_id_t slot, ck_flags_t flags,
		 void *cookie, ck_notify_t notify,
		 ck_session_handle_t *session)
{
	return o->C_OpenSession (slot, flags, cookie, notify, session);
}

P11_LITE_DEFINE (close_session, ck_session_handle_t session)
{
	return o->C_CloseSession (session);
}

P11_LITE_DEFINE (close_all_sessions, ck_slot_id_t slot)
{
	return o->C_CloseAllSessions (slot);
}

P11_LITE_DEFINE_S (get_session_info, struct ck_session_info *info)
{
	return o->C_GetSessionInfo (session, info);
}

P11_LITE_DEFINE_S (get_operation_state, void *state, unsigned long *len)
{
	return o->C_GetOperationState (session, state, len);
}

P11_LITE_DEFINE_S (set_operation_state, const void *state, size_t len,
		   ck_object_handle_t ekey, ck_object_handle_t akey)
{
	return o->C_SetOperationState (session, (void *) state, len,
				       ekey, akey);
}

P11_LITE_DEFINE_S (login, ck_user_type_t user_type, const char *pin, size_t len)
{
	return o->C_Login (session, user_type, (void *) pin, len);
}

P11_LITE_DEFINE (logout, ck_session_handle_t session)
{
	return o->C_Logout (session);
}

/* Object management functions */

P11_LITE_DEFINE_S (create_object,
		   const struct ck_attribute *templ, size_t count,
		   ck_object_handle_t *object)
{
	return o->C_CreateObject (session, (void *) templ, count, object);
}

P11_LITE_DEFINE_S (copy_object, ck_object_handle_t from,
		   const struct ck_attribute *templ, size_t count,
		   ck_object_handle_t *to)
{
	return o->C_CopyObject (session, from, (void *) templ, count, to);
}

P11_LITE_DEFINE_S (destroy_object, ck_object_handle_t object)
{
	return o->C_DestroyObject (session, object);
}

P11_LITE_DEFINE_S (get_object_size, ck_object_handle_t object, unsigned long *size)
{
	return o->C_GetObjectSize (session, object, size);
}

P11_LITE_DEFINE_S (get_attribute_value, ck_object_handle_t object,
		   struct ck_attribute *templ, size_t count)
{
	return o->C_GetAttributeValue (session, object, templ, count);
}

P11_LITE_DEFINE_S (set_attribute_value, ck_object_handle_t object,
		   const struct ck_attribute *templ, size_t count)
{
	return o->C_SetAttributeValue (session, object, (void *) templ, count);
}

P11_LITE_DEFINE_S (find_objects_init,
		   const struct ck_attribute *templ, size_t count)
{
	return o->C_FindObjectsInit (session, (void *) templ, count);
}

P11_LITE_DEFINE_S (find_objects, ck_object_handle_t *object,
		   size_t max_object_count, unsigned long *object_count)
{
	return o->C_FindObjects (session, object, max_object_count,
				 object_count);
}

P11_LITE_DEFINE (find_objects_final, ck_session_handle_t session)
{
	return o->C_FindObjectsFinal (session);
}

/* Encryption functions */

P11_LITE_DEFINE_S (encrypt_init, const struct ck_mechanism *mechanism,
		   ck_object_handle_t key)
{
	return o->C_EncryptInit (session, (void *) mechanism, key);
}

P11_LITE_DEFINE_S (encrypt, const void *in, size_t in_len,
		   void *out, unsigned long *out_len)
{
	return o->C_Encrypt (session, (void *) in, in_len, out, out_len);
}

P11_LITE_DEFINE_S (encrypt_update, const void *in, size_t in_len,
		   void *out, unsigned long *out_len)
{
	return o->C_EncryptUpdate (session, (void *) in, in_len, out, out_len);
}

P11_LITE_DEFINE_S (encrypt_final, void *out, unsigned long *out_len)
{
	return o->C_EncryptFinal (session, out, out_len);
}

/* Decryption functions */

P11_LITE_DEFINE_S (decrypt_init, const struct ck_mechanism *mechanism,
		   ck_object_handle_t key)
{
	return o->C_DecryptInit (session, (void *) mechanism, key);
}

P11_LITE_DEFINE_S (decrypt, const void *in, size_t in_len,
		   void *out, unsigned long *out_len)
{
	return o->C_Decrypt (session, (void *) in, in_len, out, out_len);
}

P11_LITE_DEFINE_S (decrypt_update, const void *in, size_t in_len,
		   void *out, unsigned long *out_len)
{
	return o->C_DecryptUpdate (session, (void *) in, in_len, out, out_len);
}

P11_LITE_DEFINE_S (decrypt_final, void *out, unsigned long *out_len)
{
	return o->C_DecryptFinal (session, out, out_len);
}

/* Message digesting functions */

P11_LITE_DEFINE_S (digest_init, const struct ck_mechanism *mechanism)
{
	return o->C_DigestInit (session, (void *) mechanism);
}

P11_LITE_DEFINE_S (digest, const void *in, size_t in_len,
		   void *out, unsigned long *out_len)
{
	return o->C_Digest (session, (void *) in, in_len, out, out_len);
}

P11_LITE_DEFINE_S (digest_update, const void *in, size_t in_len)
{
	return o->C_DigestUpdate (session, (void *) in, in_len);
}

P11_LITE_DEFINE_S (digest_key, ck_object_handle_t key)
{
	return o->C_DigestKey (session, key);
}

P11_LITE_DEFINE_S (digest_final, void *out, unsigned long *out_len)
{
	return o->C_DigestFinal (session, out, out_len);
}

/* Signing and MACing functions */

P11_LITE_DEFINE_S (sign_init, const struct ck_mechanism *mechanism,
		   ck_object_handle_t key)
{
	return o->C_SignInit (session, (void *) mechanism, key);
}

P11_LITE_DEFINE_S (sign, const void *in, size_t in_len,
		   void *sign, unsigned long *sign_len)
{
	return o->C_Sign (session, (void *) in, in_len, sign, sign_len);
}

P11_LITE_DEFINE_S (sign_update, const void *in, size_t in_len)
{
	return o->C_SignUpdate (session, (void *) in, in_len);
}

P11_LITE_DEFINE_S (sign_final, void *sign, unsigned long *sign_len)
{
	return o->C_SignFinal (session, sign, sign_len);
}

P11_LITE_DEFINE_S (sign_recover_init, const struct ck_mechanism *mechanism,
		   ck_object_handle_t key)
{
	return o->C_SignRecoverInit (session, (void *) mechanism, key);
}

P11_LITE_DEFINE_S (sign_recover, const void *in, size_t in_len,
		   void *sign, unsigned long *sign_len)
{
	return o->C_SignRecover (session, (void *) in, in_len, sign, sign_len);
}

/* Functions for verifying signatures and MACs */

P11_LITE_DEFINE_S (verify_init, const struct ck_mechanism *mechanism,
		   ck_object_handle_t key)
{
	return o->C_VerifyInit (session, (void *) mechanism, key);
}

P11_LITE_DEFINE_S (verify, const void *in, size_t in_len,
		   const void *sign, unsigned long sign_len)
{
	return o->C_Verify (session, (void *) in, in_len,
			    (void *) sign, sign_len);
}

P11_LITE_DEFINE_S (verify_update, const void *in, size_t in_len)
{
	return o->C_VerifyUpdate (session, (void *) in, in_len);
}

P11_LITE_DEFINE_S (verify_final, const void *sign, size_t sign_len)
{
	return o->C_VerifyFinal (session, (void *) sign, sign_len);
}

P11_LITE_DEFINE_S (verify_recover_init, const struct ck_mechanism *mechanism,
		   ck_object_handle_t key)
{
	return o->C_VerifyRecoverInit (session, (void *) mechanism, key);
}

P11_LITE_DEFINE_S (verify_recover, const void *sign, size_t sign_len,
		   void *out, unsigned long *out_len)
{
	return o->C_VerifyRecover (session, (void *) sign, sign_len,
				   out, out_len);
}

/* Dual-purpose cryptographic functions */

P11_LITE_DEFINE_S (digest_encrypt_update, const void *in, size_t in_len,
		   void *out, unsigned long *out_len)
{
	return o->C_DigestEncryptUpdate (session, (void *) in, in_len,
					 out, out_len);
}

P11_LITE_DEFINE_S (decrypt_digest_update, const void *in, size_t in_len,
		   void *out, unsigned long *out_len)
{
	return o->C_DecryptDigestUpdate (session, (void *) in, in_len,
					 out, out_len);
}

P11_LITE_DEFINE_S (sign_encrypt_update, const void *in, size_t in_len,
		   void *out, unsigned long *out_len)
{
	return o->C_SignEncryptUpdate (session, (void *) in, in_len,
				       out, out_len);
}

P11_LITE_DEFINE_S (decrypt_verify_update, const void *in, size_t in_len,
		   void *out, unsigned long *out_len)
{
	return o->C_DecryptVerifyUpdate (session, (void *) in, in_len,
					 out, out_len);
}

/* Key management functions */

P11_LITE_DEFINE_S (generate_key, const struct ck_mechanism *mechanism,
		   const struct ck_attribute *templ, size_t count,
		   ck_object_handle_t *key)
{
	return o->C_GenerateKey (session, (void *) mechanism,
				 (void *) templ, count, key);
}

P11_LITE_DEFINE_S (generate_key_pair, const struct ck_mechanism *mechanism,
		   const struct ck_attribute *pub_templ,  size_t pub_count,
		   const struct ck_attribute *priv_templ, size_t priv_count,
		   ck_object_handle_t *pub, ck_object_handle_t *priv)
{
	return o->C_GenerateKeyPair (session, (void *) mechanism,
				     (void *) pub_templ,  pub_count,
				     (void *) priv_templ, priv_count,
				     pub, priv);
}

P11_LITE_DEFINE_S (wrap_key, const struct ck_mechanism *mechanism,
		   ck_object_handle_t wrapping_key, ck_object_handle_t key,
		   void *out, unsigned long *len)
{
	return o->C_WrapKey (session, (void *) mechanism, wrapping_key, key,
			     out, len);
}

P11_LITE_DEFINE_S (unwrap_key, const struct ck_mechanism *mechanism,
		   ck_object_handle_t unwrapping_key,
		   const void *in, size_t in_len,
		   const struct ck_attribute *templ, size_t attr_count,
		   ck_object_handle_t *key)
{
	return o->C_UnwrapKey (session, (void *) mechanism, unwrapping_key,
			       (void *) in, in_len, (void *) templ, attr_count,
			       key);
}

P11_LITE_DEFINE_S (derive_key, const struct ck_mechanism *mechanism,
		   ck_object_handle_t base_key,
		   const struct ck_attribute *templ, size_t attr_count,
		   ck_object_handle_t *key)
{
	return o->C_DeriveKey (session, (void *) mechanism, base_key,
			       (void *) templ, attr_count, key);
}

/* Random number generation functions */

P11_LITE_DEFINE_S (seed_random, const void *in, size_t in_len)
{
	return o->C_SeedRandom (session, (void *) in, in_len);
}

P11_LITE_DEFINE_S (generate_random, void *out, size_t count)
{
	return o->C_GenerateRandom (session, out, count);
}

/* Parallel function management functions */

P11_LITE_DEFINE (get_function_status, ck_session_handle_t session)
{
	return o->C_GetFunctionStatus (session);
}

P11_LITE_DEFINE (cancel_function, ck_session_handle_t session)
{
	return o->C_CancelFunction (session);
}

#endif  /* P11_LITE_H */
