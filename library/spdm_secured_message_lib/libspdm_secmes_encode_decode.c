/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_secured_message_lib.h"
#include "internal/libspdm_requester_lib.h"

uint8_t my_libspdm_mctp_get_sequence_number(uint64_t sequence_number, uint8_t *sequence_number_buffer)
{
	libspdm_copy_mem(sequence_number_buffer, 2, &sequence_number, 2);
	return 2;
}

uint32_t my_libspdm_mctp_get_max_random_number_count(void)
{
    return 12;
}

void libspdm_build_secured_message(void *context)
{
    //libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t secured_message_size;
    uint8_t *secured_message;
    libspdm_secured_message_callbacks_t spdm_secured_message_callbacks;
    libspdm_session_info_t *session_info;
    //bool is_requester;
    uint32_t session_id;
    libspdm_secured_message_context_t *secured_message_context;
    //size_t record_header_max_size;
    //size_t transport_header_size;
    uint8_t scratch_buffer[200];
    size_t scratch_buffer_size;
    uint8_t *app_message;
    size_t app_message_size;
    uint8_t dummy_app_msg[100];
    uint16_t i;
    uint16_t nbytes;

    spdm_context = context;
    spdm_secured_message_callbacks.version = SPDM_SECURED_MESSAGE_CALLBACKS_VERSION;
    spdm_secured_message_callbacks.get_sequence_number = my_libspdm_mctp_get_sequence_number;
    spdm_secured_message_callbacks.get_max_random_number_count = my_libspdm_mctp_get_max_random_number_count;
    session_id = 0xFFFFFFFF;
//    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
//    libspdm_session_info_init(spdm_context, session_info, session_id, false);
    secured_message_context = session_info->secured_message_context;
    //secured_message_context->session_type = LIBSPDM_SESSION_TYPE_MAC_ONLY;
    //secured_message_context->session_state = LIBSPDM_SESSION_STATE_HANDSHAKING;
    //secured_message_context->aead_key_size = LIBSPDM_MAX_AEAD_KEY_SIZE;
    //secured_message_context->aead_iv_size = LIBSPDM_MAX_AEAD_IV_SIZE;

    /* limit the encoding buffer to avoid assert, because the input buffer is controlled by the the libspdm consumer. */
#if 0
    record_header_max_size = sizeof(spdm_secured_message_a_data_header1_t) +
                             2 + /* MCTP_SEQUENCE_NUMBER_COUNT */
                             sizeof(spdm_secured_message_a_data_header2_t) +
                             sizeof(spdm_secured_message_cipher_header_t) +
                             32; /* MCTP_MAX_RANDOM_NUMBER_COUNT */
#endif
  //  LIBSPDM_ASSERT(spdm_test_context->test_buffer_size > record_header_max_size);

    /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
     * transport_message is always in sender buffer. */
    //libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);
    scratch_buffer_size = 200;
    for (i = 0; i < 50; i++)
    	dummy_app_msg[i+10] = i;

#if 0
    libspdm_copy_mem (scratch_buffer + record_header_max_size,
                      scratch_buffer_size - record_header_max_size,
                      (uint8_t *)spdm_test_context->test_buffer + record_header_max_size,
                      spdm_test_context->test_buffer_size - record_header_max_size);
#endif
    app_message = dummy_app_msg + 10;
    app_message_size = 50;

    //transport_header_size = libspdm_transport_mctp_get_header_size(spdm_context);
    //secured_message = (uint8_t *)spdm_test_context->test_buffer + transport_header_size;
    //secured_message_size = LIBSPDM_MAX_MESSAGE_BUFFER_SIZE - transport_header_size;

    secured_message = scratch_buffer;
    secured_message_size = scratch_buffer_size;

    libspdm_encode_secured_message(secured_message_context, session_id, true,
                                   app_message_size,
                                   app_message,
                                   &secured_message_size, secured_message,
                                   &spdm_secured_message_callbacks);

    nbytes = 8;
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "secured_message Encrypted Data - \n"));
    for (i = 0; i < secured_message_size-16; i+=8) {
    	if (i + 8 >= secured_message_size - 16)
    		nbytes = secured_message_size - 16 - i;
    	LIBSPDM_INTERNAL_DUMP_DATA(secured_message + i, nbytes);
    	LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\nSecured message MAC - \n"));
    LIBSPDM_INTERNAL_DUMP_DATA(secured_message + i, 8);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));
    LIBSPDM_INTERNAL_DUMP_DATA(secured_message + i + 8, 8);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));

}

/**
 * Encode an application message to a secured message.
 *
 * @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
 * @param  session_id                    The session ID of the SPDM session.
 * @param  is_requester                  Indicates if it is a requester message.
 * @param  app_message_size               size in bytes of the application message data buffer.
 * @param  app_message                   A pointer to a source buffer to store the application message.
 *                                       It shall point to the scratch buffer in spdm_context.
 *                                         Before app_message, there is room for spdm_secured_message_cipher_header_t.
 *                                         After (app_message + app_message_size), there is room for random bytes.
 * @param  secured_message_size           size in bytes of the secured message data buffer.
 * @param  secured_message               A pointer to a destination buffer to store the secured message.
 *                                       It shall point to the acquired sender buffer.
 * @param  spdm_secured_message_callbacks  A pointer to a secured message callback functions structure.
 *
 * @retval RETURN_SUCCESS               The application message is encoded successfully.
 * @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
 **/
libspdm_return_t libspdm_encode_secured_message(
    void *spdm_secured_message_context, uint32_t session_id,
    bool is_requester, size_t app_message_size,
    void *app_message, size_t *secured_message_size,
    void *secured_message,
    const libspdm_secured_message_callbacks_t *spdm_secured_message_callbacks)
{
    libspdm_secured_message_context_t *secured_message_context;
    size_t total_secured_message_size;
    size_t plain_text_size;
    size_t cipher_text_size;
    size_t aead_pad_size;
    size_t aead_tag_size;
    size_t aead_key_size;
    size_t aead_iv_size;
    uint8_t *a_data;
    uint8_t *enc_msg;
    uint8_t *dec_msg;
    uint8_t *tag;
    spdm_secured_message_a_data_header1_t *record_header1;
    spdm_secured_message_a_data_header2_t *record_header2;
    size_t record_header_size;
    spdm_secured_message_cipher_header_t *enc_msg_header;
    bool result;
    const uint8_t *key;
    uint8_t *salt;
    uint64_t sequence_number;
    uint64_t sequence_num_in_header;
    uint64_t data64;
    uint8_t sequence_num_in_header_size;
    libspdm_session_type_t session_type;
    uint32_t rand_count;
    uint32_t max_rand_count;
    libspdm_session_state_t session_state;
    uint8_t *ptr, i;

    secured_message_context = spdm_secured_message_context;

    session_type = secured_message_context->session_type;
    LIBSPDM_ASSERT((session_type == LIBSPDM_SESSION_TYPE_MAC_ONLY) ||
                   (session_type == LIBSPDM_SESSION_TYPE_ENC_MAC));
    session_state = secured_message_context->session_state;
    LIBSPDM_ASSERT((session_state == LIBSPDM_SESSION_STATE_HANDSHAKING) ||
                   (session_state == LIBSPDM_SESSION_STATE_ESTABLISHED));

    aead_tag_size = secured_message_context->aead_tag_size;
    aead_key_size = secured_message_context->aead_key_size;
    aead_iv_size = secured_message_context->aead_iv_size;

    switch (session_state) {
    case LIBSPDM_SESSION_STATE_HANDSHAKING:
        if (is_requester) {
            key = (const uint8_t *)secured_message_context->handshake_secret.
                  request_handshake_encryption_key;
            salt = (uint8_t *)secured_message_context->handshake_secret.
                   request_handshake_salt;
            sequence_number = secured_message_context->handshake_secret
                              .request_handshake_sequence_number;
        } else {
            key = (const uint8_t *)secured_message_context->handshake_secret.
                  response_handshake_encryption_key;
            salt = (uint8_t *)secured_message_context->handshake_secret.
                   response_handshake_salt;
            sequence_number = secured_message_context->handshake_secret
                              .response_handshake_sequence_number;
        }
        break;
    case LIBSPDM_SESSION_STATE_ESTABLISHED:
        if (is_requester) {
            key = (const uint8_t *)secured_message_context->application_secret.
                  request_data_encryption_key;
            salt = (uint8_t *)secured_message_context->application_secret.
                   request_data_salt;
            sequence_number = secured_message_context->application_secret
                              .request_data_sequence_number;
        } else {
            key = (const uint8_t *)secured_message_context->application_secret.
                  response_data_encryption_key;
            salt = (uint8_t *)secured_message_context->application_secret.
                   response_data_salt;
            sequence_number = secured_message_context->application_secret
                              .response_data_sequence_number;
        }
        break;
    default:
        LIBSPDM_ASSERT(false);
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        break;
    }

    if (sequence_number == (uint64_t)-1) {
        return LIBSPDM_STATUS_SEQUENCE_NUMBER_OVERFLOW;
    }

    if (sequence_number > 0) {
        data64 = libspdm_read_uint64((const uint8_t *)salt) ^
                 (sequence_number - 1) ^ sequence_number;
        libspdm_write_uint64(salt, data64);
    }

    sequence_num_in_header = 0;
    sequence_num_in_header_size = spdm_secured_message_callbacks->get_sequence_number(
        sequence_number, (uint8_t *)&sequence_num_in_header);
    LIBSPDM_ASSERT(sequence_num_in_header_size <= sizeof(sequence_num_in_header));

    sequence_number++;
    if (session_state == LIBSPDM_SESSION_STATE_HANDSHAKING) {
        if (is_requester) {
            secured_message_context->handshake_secret.request_handshake_sequence_number =
                sequence_number;
        } else {
            secured_message_context->handshake_secret.response_handshake_sequence_number =
                sequence_number;
        }
    }
    else {
        if (is_requester) {
            secured_message_context->application_secret.request_data_sequence_number =
                sequence_number;
        } else {
            secured_message_context->application_secret.response_data_sequence_number =
                sequence_number;
        }
    }

    record_header_size = sizeof(spdm_secured_message_a_data_header1_t) +
                         sequence_num_in_header_size +
                         sizeof(spdm_secured_message_a_data_header2_t);

    switch (session_type) {
    case LIBSPDM_SESSION_TYPE_ENC_MAC:
        max_rand_count = spdm_secured_message_callbacks->get_max_random_number_count();
        if (max_rand_count != 0) {
            rand_count = 0;
            result = libspdm_get_random_number(sizeof(rand_count), (uint8_t *)&rand_count);
            if (!result) {
                return LIBSPDM_STATUS_LOW_ENTROPY;
            }
            rand_count = (uint8_t)((rand_count % max_rand_count) + 1);
        } else {
            rand_count = 0;
        }

        rand_count = 12;
        plain_text_size = sizeof(spdm_secured_message_cipher_header_t) + app_message_size +
                          rand_count;
        cipher_text_size = plain_text_size;
        aead_pad_size = cipher_text_size - plain_text_size;
        total_secured_message_size = record_header_size + cipher_text_size + aead_tag_size;

        LIBSPDM_ASSERT(*secured_message_size >= total_secured_message_size);
        if (*secured_message_size < total_secured_message_size) {
            *secured_message_size = total_secured_message_size;
            return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
        }
        *secured_message_size = total_secured_message_size;
        record_header1 = (void *)secured_message;
        record_header2 = (void *)((uint8_t *)record_header1 +
                                  sizeof(spdm_secured_message_a_data_header1_t) +
                                  sequence_num_in_header_size);
        record_header1->session_id = session_id;
        libspdm_copy_mem(record_header1 + 1,
                         *secured_message_size
                         - ((uint8_t*)(record_header1 + 1) - (uint8_t*)secured_message),
                         &sequence_num_in_header,
                         sequence_num_in_header_size);
        record_header2->length = (uint16_t)(cipher_text_size + aead_tag_size);

        enc_msg_header =
            (void *)((uint8_t *)app_message - sizeof(spdm_secured_message_cipher_header_t));
        enc_msg_header->application_data_length = (uint16_t)app_message_size;
#if 0
        result = libspdm_get_random_number(rand_count,
                                           (uint8_t *)enc_msg_header +
                                           sizeof(spdm_secured_message_cipher_header_t) +
                                           app_message_size);
        if (!result) {
            return LIBSPDM_STATUS_LOW_ENTROPY;
        }
#endif
        ptr = (uint8_t *)enc_msg_header +
                        sizeof(spdm_secured_message_cipher_header_t) +
                        app_message_size;
        for (i = 0; i < 12; i++)
        	ptr[i] = i;

        libspdm_zero_mem((uint8_t *)enc_msg_header + plain_text_size, aead_pad_size);

        a_data = (uint8_t *)record_header1;
        enc_msg = (uint8_t *)(record_header2 + 1);
        dec_msg = (uint8_t *)enc_msg_header;
        tag = (uint8_t *)record_header1 + record_header_size +
              cipher_text_size;

        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "encryption key - "));
        LIBSPDM_INTERNAL_DUMP_DATA(key, aead_key_size);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));

        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "IV - "));
        LIBSPDM_INTERNAL_DUMP_DATA(salt, aead_iv_size);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));

        result = libspdm_aead_encryption(
            secured_message_context->secured_message_version,
            secured_message_context->aead_cipher_suite, key,
            aead_key_size, salt, aead_iv_size, (uint8_t *)a_data,
            record_header_size, dec_msg, cipher_text_size, tag,
            aead_tag_size, enc_msg, &cipher_text_size);
        break;

    case LIBSPDM_SESSION_TYPE_MAC_ONLY:
        total_secured_message_size =
            record_header_size + app_message_size + aead_tag_size;

        LIBSPDM_ASSERT(*secured_message_size >= total_secured_message_size);
        if (*secured_message_size < total_secured_message_size) {
            *secured_message_size = total_secured_message_size;
            return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
        }
        *secured_message_size = total_secured_message_size;
        record_header1 = (void *)secured_message;
        record_header2 =
            (void *)((uint8_t *)record_header1 +
                     sizeof(spdm_secured_message_a_data_header1_t) +
                     sequence_num_in_header_size);
        record_header1->session_id = session_id;
        libspdm_copy_mem(record_header1 + 1,
                         *secured_message_size
                         - ((uint8_t*)(record_header1 + 1) - (uint8_t*)secured_message),
                         &sequence_num_in_header,
                         sequence_num_in_header_size);
        record_header2->length =
            (uint16_t)(app_message_size + aead_tag_size);
        libspdm_copy_mem(record_header2 + 1,
                         *secured_message_size
                         - ((uint8_t*)(record_header2 + 1) - (uint8_t*)secured_message),
                         app_message, app_message_size);
        a_data = (uint8_t *)record_header1;
        tag = (uint8_t *)record_header1 + record_header_size + app_message_size;

        result = libspdm_aead_encryption(
            secured_message_context->secured_message_version,
            secured_message_context->aead_cipher_suite, key,
            aead_key_size, salt, aead_iv_size, (uint8_t *)a_data,
            record_header_size + app_message_size, NULL, 0, tag,
            aead_tag_size, NULL, NULL);
        break;

    default:
        LIBSPDM_ASSERT(false);
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }
    if (!result) {
        return LIBSPDM_STATUS_CRYPTO_ERROR;
    }
    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * Decode an application message from a secured message.
 *
 * @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
 * @param  session_id                    The session ID of the SPDM session.
 * @param  is_requester                  Indicates if it is a requester message.
 * @param  secured_message_size           size in bytes of the secured message data buffer.
 * @param  secured_message               A pointer to a source buffer to store the secured message.
 *                                       It shall point to the acquired receiver buffer.
 * @param  app_message_size               size in bytes of the application message data buffer.
 * @param  app_message                   A pointer to a destination buffer to store the application message.
 *                                       It shall point to the scratch buffer in spdm_context.
 *                                       On input, the app_message pointer shall point to a big enough buffer to hold the decrypted message
 *                                       On output, the app_message pointer shall be inside of [app_message, app_message + app_message_size]
 * @param  spdm_secured_message_callbacks  A pointer to a secured message callback functions structure.
 *
 * @retval RETURN_SUCCESS               The application message is decoded successfully.
 * @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
 * @retval RETURN_UNSUPPORTED           The secured_message is unsupported.
 **/
libspdm_return_t libspdm_decode_secured_message(
    void *spdm_secured_message_context, uint32_t session_id,
    bool is_requester, size_t secured_message_size,
    void *secured_message, size_t *app_message_size,
    void **app_message,
    const libspdm_secured_message_callbacks_t *spdm_secured_message_callbacks)
{
    libspdm_secured_message_context_t *secured_message_context;
    size_t plain_text_size;
    size_t cipher_text_size;
    size_t aead_tag_size;
    size_t aead_key_size;
    size_t aead_iv_size;
    const uint8_t *a_data;
    const uint8_t *enc_msg;
    uint8_t *dec_msg;
    const uint8_t *tag;
    spdm_secured_message_a_data_header1_t *record_header1;
    spdm_secured_message_a_data_header2_t *record_header2;
    size_t record_header_size;
    spdm_secured_message_cipher_header_t *enc_msg_header;
    bool result;
    const uint8_t *key;
    uint8_t *salt;
    uint64_t sequence_number;
    uint64_t sequence_num_in_header;
    uint64_t data64;
    uint8_t sequence_num_in_header_size;
    libspdm_session_type_t session_type;
    libspdm_session_state_t session_state;
    libspdm_error_struct_t spdm_error;

    spdm_error.error_code = 0;
    spdm_error.session_id = 0;
    libspdm_secured_message_set_last_spdm_error_struct(spdm_secured_message_context, &spdm_error);

    spdm_error.error_code = SPDM_ERROR_CODE_DECRYPT_ERROR;
    spdm_error.session_id = session_id;

    secured_message_context = spdm_secured_message_context;

    session_type = secured_message_context->session_type;
    LIBSPDM_ASSERT((session_type == LIBSPDM_SESSION_TYPE_MAC_ONLY) ||
                   (session_type == LIBSPDM_SESSION_TYPE_ENC_MAC));
    session_state = secured_message_context->session_state;
    LIBSPDM_ASSERT((session_state == LIBSPDM_SESSION_STATE_HANDSHAKING) ||
                   (session_state == LIBSPDM_SESSION_STATE_ESTABLISHED));

    aead_tag_size = secured_message_context->aead_tag_size;
    aead_key_size = secured_message_context->aead_key_size;
    aead_iv_size = secured_message_context->aead_iv_size;

    switch (session_state) {
    case LIBSPDM_SESSION_STATE_HANDSHAKING:
        if (is_requester) {
            key = (const uint8_t *)secured_message_context->handshake_secret.
                  request_handshake_encryption_key;
            salt = (uint8_t *)secured_message_context->handshake_secret.
                   request_handshake_salt;
            sequence_number =
                secured_message_context->handshake_secret.request_handshake_sequence_number;
        } else {
            key = (const uint8_t *)secured_message_context->handshake_secret.
                  response_handshake_encryption_key;
            salt = (uint8_t *)secured_message_context->handshake_secret.
                   response_handshake_salt;
            sequence_number =
                secured_message_context->handshake_secret.response_handshake_sequence_number;
        }
        break;
    case LIBSPDM_SESSION_STATE_ESTABLISHED:
        if (is_requester) {
            key = (const uint8_t *)secured_message_context->application_secret.
                  request_data_encryption_key;
            salt = (uint8_t *)secured_message_context->application_secret.
                   request_data_salt;
            sequence_number =
                secured_message_context->application_secret.request_data_sequence_number;
        } else {
            key = (const uint8_t *)secured_message_context->application_secret.
                  response_data_encryption_key;
            salt = (uint8_t *)secured_message_context->application_secret.
                   response_data_salt;
            sequence_number =
                secured_message_context->application_secret.response_data_sequence_number;
        }
        break;
    default:
        LIBSPDM_ASSERT(false);
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    if (sequence_number == (uint64_t)-1) {
        libspdm_secured_message_set_last_spdm_error_struct(
            spdm_secured_message_context, &spdm_error);
        return LIBSPDM_STATUS_SEQUENCE_NUMBER_OVERFLOW;
    }

    if (sequence_number > 0) {
        data64 = libspdm_read_uint64((const uint8_t *)salt) ^
                 (sequence_number - 1) ^ sequence_number;
        libspdm_write_uint64(salt, data64);
    }

    sequence_num_in_header = 0;
    sequence_num_in_header_size =
        spdm_secured_message_callbacks->get_sequence_number(
            sequence_number, (uint8_t *)&sequence_num_in_header);
    LIBSPDM_ASSERT(sequence_num_in_header_size <= sizeof(sequence_num_in_header));

    sequence_number++;
    if (session_state == LIBSPDM_SESSION_STATE_HANDSHAKING) {
        if (is_requester) {
            secured_message_context->handshake_secret.request_handshake_sequence_number =
                sequence_number;
        } else {
            secured_message_context->handshake_secret.response_handshake_sequence_number =
                sequence_number;
        }
    }
    else {
        if (is_requester) {
            secured_message_context->application_secret.request_data_sequence_number =
                sequence_number;
        } else {
            secured_message_context->application_secret.response_data_sequence_number =
                sequence_number;
        }
    }

    record_header_size = sizeof(spdm_secured_message_a_data_header1_t) +
                         sequence_num_in_header_size +
                         sizeof(spdm_secured_message_a_data_header2_t);

    switch (session_type) {
    case LIBSPDM_SESSION_TYPE_ENC_MAC:
        if (secured_message_size < record_header_size + aead_tag_size) {
            libspdm_secured_message_set_last_spdm_error_struct(
                spdm_secured_message_context, &spdm_error);
            return LIBSPDM_STATUS_INVALID_MSG_SIZE;
        }
        record_header1 = secured_message;
        record_header2 =
            (void *)((uint8_t *)record_header1 +
                     sizeof(spdm_secured_message_a_data_header1_t) +
                     sequence_num_in_header_size);
        if (record_header1->session_id != session_id) {
            libspdm_secured_message_set_last_spdm_error_struct(
                spdm_secured_message_context, &spdm_error);
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
        if (libspdm_const_compare_mem(record_header1 + 1, &sequence_num_in_header,
                                      sequence_num_in_header_size) != 0) {
            libspdm_secured_message_set_last_spdm_error_struct(
                spdm_secured_message_context, &spdm_error);
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
        if (record_header2->length > secured_message_size - record_header_size) {
            libspdm_secured_message_set_last_spdm_error_struct(
                spdm_secured_message_context, &spdm_error);
            return LIBSPDM_STATUS_INVALID_MSG_SIZE;
        }
        if (record_header2->length < aead_tag_size) {
            libspdm_secured_message_set_last_spdm_error_struct(
                spdm_secured_message_context, &spdm_error);
            return LIBSPDM_STATUS_INVALID_MSG_SIZE;
        }
        cipher_text_size = (record_header2->length - aead_tag_size);
        if (cipher_text_size > *app_message_size) {
            return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
        }
        libspdm_zero_mem(*app_message, *app_message_size);
        enc_msg_header = (void *)(record_header2 + 1);
        a_data = (const uint8_t *)record_header1;
        enc_msg = (const uint8_t *)enc_msg_header;
        dec_msg = (uint8_t *)*app_message;
        enc_msg_header = (void *)dec_msg;
        tag = (const uint8_t *)record_header1 + record_header_size + cipher_text_size;
        result = libspdm_aead_decryption(
            secured_message_context->secured_message_version,
            secured_message_context->aead_cipher_suite, key,
            aead_key_size, salt, aead_iv_size, a_data,
            record_header_size, enc_msg, cipher_text_size, tag,
            aead_tag_size, dec_msg, &cipher_text_size);
        if (!result) {
            /* Backup keys are valid, fail and alert rollback and retry is possible. */
            if ((is_requester && secured_message_context->requester_backup_valid) ||
                ((!is_requester) && secured_message_context->responder_backup_valid)) {
                return LIBSPDM_STATUS_SESSION_TRY_DISCARD_KEY_UPDATE;
            }

            libspdm_secured_message_set_last_spdm_error_struct(
                spdm_secured_message_context, &spdm_error);
            return LIBSPDM_STATUS_CRYPTO_ERROR;
        }
        plain_text_size = enc_msg_header->application_data_length;
        if (plain_text_size > cipher_text_size) {
            libspdm_secured_message_set_last_spdm_error_struct(
                spdm_secured_message_context, &spdm_error);
            return LIBSPDM_STATUS_INVALID_MSG_SIZE;
        }

        LIBSPDM_ASSERT(*app_message_size >= plain_text_size);
        *app_message = enc_msg_header + 1;
        *app_message_size = plain_text_size;
        break;

    case LIBSPDM_SESSION_TYPE_MAC_ONLY:
        if (secured_message_size < record_header_size + aead_tag_size) {
            libspdm_secured_message_set_last_spdm_error_struct(
                spdm_secured_message_context, &spdm_error);
            return LIBSPDM_STATUS_INVALID_MSG_SIZE;
        }
        record_header1 = secured_message;
        record_header2 =
            (void *)((uint8_t *)record_header1 +
                     sizeof(spdm_secured_message_a_data_header1_t) +
                     sequence_num_in_header_size);
        if (record_header1->session_id != session_id) {
            libspdm_secured_message_set_last_spdm_error_struct(
                spdm_secured_message_context, &spdm_error);
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
        if (libspdm_const_compare_mem(record_header1 + 1, &sequence_num_in_header,
                                      sequence_num_in_header_size) != 0) {
            libspdm_secured_message_set_last_spdm_error_struct(
                spdm_secured_message_context, &spdm_error);
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
        if (record_header2->length >
            secured_message_size - record_header_size) {
            libspdm_secured_message_set_last_spdm_error_struct(
                spdm_secured_message_context, &spdm_error);
            return LIBSPDM_STATUS_INVALID_MSG_SIZE;
        }
        if (record_header2->length < aead_tag_size) {
            libspdm_secured_message_set_last_spdm_error_struct(
                spdm_secured_message_context, &spdm_error);
            return LIBSPDM_STATUS_INVALID_MSG_SIZE;
        }
        a_data = (uint8_t *)record_header1;
        tag = (uint8_t *)record_header1 + record_header_size +
              record_header2->length - aead_tag_size;
        result = libspdm_aead_decryption(
            secured_message_context->secured_message_version,
            secured_message_context->aead_cipher_suite, key,
            aead_key_size, salt, aead_iv_size, a_data,
            record_header_size + record_header2->length -
            aead_tag_size,
            NULL, 0, tag, aead_tag_size, NULL, NULL);
        if (!result) {
            /* Backup keys are valid, fail and alert rollback and retry is possible. */
            if ((is_requester && secured_message_context->requester_backup_valid) ||
                ((!is_requester) && secured_message_context->responder_backup_valid)) {
                return LIBSPDM_STATUS_SESSION_TRY_DISCARD_KEY_UPDATE;
            }

            libspdm_secured_message_set_last_spdm_error_struct(
                spdm_secured_message_context, &spdm_error);
            return LIBSPDM_STATUS_CRYPTO_ERROR;
        }

        plain_text_size = record_header2->length - aead_tag_size;
        LIBSPDM_ASSERT(*app_message_size >= plain_text_size);
        *app_message = record_header2 + 1;
        *app_message_size = plain_text_size;
        break;

    default:
        LIBSPDM_ASSERT(false);
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    return LIBSPDM_STATUS_SUCCESS;
}
