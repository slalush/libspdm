/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"
#include "stdio.h"

struct fw_direct_cmd_header {
	uint32_t req_msg_code;
	uint32_t req_msg_size;
	uint32_t rsp_msg_code;
	uint32_t rsp_msg_size;
};

libspdm_return_t spdm_read_cmds_from_file(void *context)
{
    FILE *ptr;
    libspdm_context_t *spdm_context = context;
    uint32_t total_size;
    size_t n_read_bytes;
    uint32_t *fw_direct_rsp_mem_buf;

    ptr = fopen("//home//ewurmbra//slalush//spdm-emu//spdm_emu//spdm_requester_emu//spdm_cmds.bin","rb");  // r for read, b for binary
//    ptr = fopen("spdm_resp2.bin","rb");  // r for read, b for binary

    n_read_bytes = fread((void *)&total_size,sizeof(uint32_t),1,ptr); // read 10 bytes to our buffer
    if (!n_read_bytes)
	return LIBSPDM_STATUS_INVALID_MSG_SIZE;

    libspdm_init_managed_buffer((void *)&spdm_context->fw_direct_rsp_mem, LIBSPDM_MAX_MESSAGE_LARGE_BUFFER_SIZE);

    fw_direct_rsp_mem_buf = libspdm_get_managed_buffer((void *)&spdm_context->fw_direct_rsp_mem);

    n_read_bytes = fread((void *)fw_direct_rsp_mem_buf, total_size, 1, ptr); // read 10 bytes to our buffer
//    if (n_read_bytes != total_size)
//	return LIBSPDM_STATUS_INVALID_MSG_SIZE;

    spdm_context->fw_direct_rsp_mem.max_buffer_size = total_size;

    fclose(ptr);

    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t spdm_read_pk_from_file(void *context)
{
    FILE *ptr;
    libspdm_context_t *spdm_context = context;
    uint32_t total_size = 96;
    uint8_t temp;
    int i;
    //size_t n_read_bytes2;
    libspdm_data_parameter_t parameter;

//    ptr = fopen("//home//ewurmbra//slalush//spdm-emu//spdm_emu//spdm_requester_emu//spdm_resp2.bin","rb");  // r for read, b for binary
    ptr = fopen("//home//ewurmbra//slalush//spdm-emu//spdm_emu//spdm_requester_emu//spdm_pk_be.bin","rb");  // r for read, b for binary

    (void)fread((void *)spdm_context->public_key, total_size, 1, ptr); // read 10 bytes to our buffer
    //if (n_read_bytes2 != total_size)
//	return LIBSPDM_STATUS_SUCCESS;

    for(i = 0; i < 76; i += 4) {
	    temp =  spdm_context->public_key[i];
	    spdm_context->public_key[i] = spdm_context->public_key[i+3];
	    spdm_context->public_key[i+3] = temp;

	    temp =  spdm_context->public_key[i+1];
	    spdm_context->public_key[i+1] = spdm_context->public_key[i+2];
	    spdm_context->public_key[i+2] = temp;
    }

    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_PEER_PUBLIC_KEY, &parameter,
		    (void *)spdm_context->public_key, 96);

    fclose(ptr);

    return 0;
}

uint16_t fw_direct_index;

libspdm_return_t spdm_verify_response_msg(void *context)
{
    libspdm_context_t *spdm_context = context;
    struct fw_direct_cmd_header *header;
    libspdm_return_t status;
    libspdm_get_spdm_requester_func get_request_func;
    uint8_t my_response[LIBSPDM_MAX_MESSAGE_MEDIUM_BUFFER_SIZE];
    size_t my_response_size = LIBSPDM_MAX_MESSAGE_MEDIUM_BUFFER_SIZE;
    uint8_t my_request[LIBSPDM_MAX_MESSAGE_MEDIUM_BUFFER_SIZE];
    size_t my_request_size = LIBSPDM_MAX_MESSAGE_MEDIUM_BUFFER_SIZE;
    size_t total_size = spdm_context->fw_direct_rsp_mem.max_buffer_size - sizeof(uint32_t);
    //uint8_t alignment = sizeof(uint32_t) -1;
    //size_t aligned_msg_size;
    //uint8_t bytes_2_align;
    //uint8_t n_misalign;

    fw_direct_index = spdm_context->fw_direct_rsp_mem.buffer_size;

    while (fw_direct_index < total_size) {
	    header = (struct fw_direct_cmd_header *)&spdm_context->fw_direct_rsp_mem.buffer[fw_direct_index];

	    my_request_size = header->req_msg_size;
	    my_response_size = header->rsp_msg_size;
	    fw_direct_index += sizeof(struct fw_direct_cmd_header);

	    get_request_func = libspdm_get_request_func_via_request_code(header->req_msg_code);
	    if (get_request_func == NULL) {
		    return LIBSPDM_STATUS_INVALID_PARAMETER;
	    }

	    libspdm_copy_mem((void *)my_request, header->req_msg_size, (const void *)&spdm_context->fw_direct_rsp_mem.buffer[fw_direct_index], header->req_msg_size);

	    fw_direct_index += header->req_msg_size;

	    libspdm_copy_mem((void *)my_response, header->rsp_msg_size, (const void *)&spdm_context->fw_direct_rsp_mem.buffer[fw_direct_index], header->rsp_msg_size);

	    fw_direct_index += header->rsp_msg_size;

	    status = get_request_func(spdm_context,
				       my_request_size,
				       my_request,
				       my_response_size, my_response);

	    if (LIBSPDM_STATUS_IS_ERROR(status)) {
		    return status;
	    }
    }

    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t libspdm_init_connection(void *spdm_context, bool get_version_only)
{
    libspdm_return_t status;
    libspdm_context_t *context;

    context = spdm_context;

    status = libspdm_get_version(context, NULL, NULL);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    if (!get_version_only) {
        status = libspdm_get_capabilities(context);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return status;
        }
        status = libspdm_negotiate_algorithms(context);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return status;
        }
    }
    return LIBSPDM_STATUS_SUCCESS;
}

#if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP)
libspdm_return_t libspdm_start_session(void *spdm_context, bool use_psk,
                                       uint8_t measurement_hash_type,
                                       uint8_t slot_id,
                                       uint8_t session_policy,
                                       uint32_t *session_id,
                                       uint8_t *heartbeat_period,
                                       void *measurement_hash)
{
    libspdm_return_t status;
    libspdm_context_t *context;

    #if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP
    libspdm_session_info_t *session_info;
    uint8_t req_slot_id_param;
    #endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/

    context = spdm_context;
    status = LIBSPDM_STATUS_UNSUPPORTED_CAP;

    if (!use_psk) {
    #if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP
        status = libspdm_send_receive_key_exchange(
            context, measurement_hash_type, slot_id, session_policy,
            session_id, heartbeat_period, &req_slot_id_param,
            measurement_hash);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                           "libspdm_start_session - libspdm_send_receive_key_exchange - %p\n",
                           status));
            return status;
        }

        session_info = libspdm_get_session_info_via_session_id(context, *session_id);
        if (session_info == NULL) {
            LIBSPDM_ASSERT(false);
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }

        switch (session_info->mut_auth_requested) {
        case 0:
            break;
        case SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED:
#if !(LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP)
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                           "libspdm_start_session - unsupported mut_auth_requested - 0x%x\n",
                           session_info->mut_auth_requested));
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
#endif
            break;
        case SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST:
        case SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS:
#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) || (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP)
            status = libspdm_encapsulated_request(
                context, session_id,
                session_info->mut_auth_requested,
                &req_slot_id_param);
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                           "libspdm_start_session - libspdm_encapsulated_request - %p\n", status));
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                return status;
            }
#else
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                           "libspdm_start_session - unsupported mut_auth_requested - 0x%x\n",
                           session_info->mut_auth_requested));
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
#endif
            break;
        default:
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                           "libspdm_start_session - unknown mut_auth_requested - 0x%x\n",
                           session_info->mut_auth_requested));
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }

        if (req_slot_id_param == 0xF) {
            req_slot_id_param = 0xFF;
        }
        status = libspdm_send_receive_finish(context, *session_id, req_slot_id_param);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "libspdm_start_session - libspdm_send_receive_finish - %p\n", status));
    #else /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/
        LIBSPDM_ASSERT(false);
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    #endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/
    } else {
    #if LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP
        status = libspdm_send_receive_psk_exchange(
            context, measurement_hash_type, session_policy, session_id,
            heartbeat_period, measurement_hash);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                           "libspdm_start_session - libspdm_send_receive_psk_exchange - %p\n",
                           status));
            return status;
        }

        /* send PSK_FINISH only if Responder supports context.*/
        if (libspdm_is_capabilities_flag_supported(
                context, true, 0,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT)) {
            status = libspdm_send_receive_psk_finish(context, *session_id);
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                           "libspdm_start_session - libspdm_send_receive_psk_finish - %p\n",
                           status));
        }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP*/
    }
    return status;
}

libspdm_return_t libspdm_start_session_ex(void *spdm_context, bool use_psk,
                                          uint8_t measurement_hash_type,
                                          uint8_t slot_id,
                                          uint8_t session_policy,
                                          uint32_t *session_id,
                                          uint8_t *heartbeat_period,
                                          void *measurement_hash,
                                          const void *requester_random_in,
                                          size_t requester_random_in_size,
                                          void *requester_random,
                                          size_t *requester_random_size,
                                          void *responder_random,
                                          size_t *responder_random_size)
{
    libspdm_return_t status;
    libspdm_context_t *context;

    #if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP
    libspdm_session_info_t *session_info;
    uint8_t req_slot_id_param;
    #endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP */

    context = spdm_context;
    status = LIBSPDM_STATUS_UNSUPPORTED_CAP;

    if (!use_psk) {
    #if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP
        LIBSPDM_ASSERT (
            requester_random_in_size == 0 || requester_random_in_size == SPDM_RANDOM_DATA_SIZE);
        LIBSPDM_ASSERT (
            requester_random_size == NULL || *requester_random_size == SPDM_RANDOM_DATA_SIZE);
        LIBSPDM_ASSERT (
            responder_random_size == NULL || *responder_random_size == SPDM_RANDOM_DATA_SIZE);
        status = libspdm_send_receive_key_exchange_ex(
            context, measurement_hash_type, slot_id, session_policy,
            session_id, heartbeat_period, &req_slot_id_param,
            measurement_hash, requester_random_in,
            requester_random, responder_random);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                           "libspdm_start_session - libspdm_send_receive_key_exchange - %p\n",
                           status));
            return status;
        }

        session_info = libspdm_get_session_info_via_session_id(context, *session_id);
        if (session_info == NULL) {
            LIBSPDM_ASSERT(false);
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }

        switch (session_info->mut_auth_requested) {
        case 0:
            break;
        case SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED:
#if !(LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP)
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                           "libspdm_start_session - unsupported mut_auth_requested - 0x%x\n",
                           session_info->mut_auth_requested));
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
#endif
            break;
        case SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST:
        case SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS:
#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) || (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP)
            status = libspdm_encapsulated_request(
                context, session_id,
                session_info->mut_auth_requested,
                &req_slot_id_param);
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                           "libspdm_start_session - libspdm_encapsulated_request - %p\n", status));
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                return status;
            }
#else
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                           "libspdm_start_session - unsupported mut_auth_requested - 0x%x\n",
                           session_info->mut_auth_requested));
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
#endif
            break;
        default:
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                           "libspdm_start_session - unknown mut_auth_requested - 0x%x\n",
                           session_info->mut_auth_requested));
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }

        if (req_slot_id_param == 0xF) {
            req_slot_id_param = 0xFF;
        }
        status = libspdm_send_receive_finish(context, *session_id, req_slot_id_param);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "libspdm_start_session - libspdm_send_receive_finish - %p\n", status));
    #else /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/
        LIBSPDM_ASSERT(false);
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    #endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/
    } else {
    #if LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP
        status = libspdm_send_receive_psk_exchange_ex(
            context, measurement_hash_type, session_policy, session_id,
            heartbeat_period, measurement_hash,
            requester_random_in, requester_random_in_size,
            requester_random, requester_random_size,
            responder_random, responder_random_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                           "libspdm_start_session - libspdm_send_receive_psk_exchange - %p\n",
                           status));
            return status;
        }

        /* send PSK_FINISH only if Responder supports context.*/
        if (libspdm_is_capabilities_flag_supported(
                context, true, 0,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT)) {
            status = libspdm_send_receive_psk_finish(context, *session_id);
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                           "libspdm_start_session - libspdm_send_receive_psk_finish - %p\n",
                           status));
        }
    #else /* LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP*/
        LIBSPDM_ASSERT(false);
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    #endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP*/
    }

    return status;
}

libspdm_return_t libspdm_stop_session(void *spdm_context, uint32_t session_id,
                                      uint8_t end_session_attributes)
{
    libspdm_return_t status;
    libspdm_context_t *context;

    context = spdm_context;

    status = libspdm_send_receive_end_session(context, session_id, end_session_attributes);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "libspdm_stop_session - %p\n", status));

    return status;
}
#endif /* (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP) */

libspdm_return_t libspdm_send_receive_data(void *spdm_context, const uint32_t *session_id,
                                           bool is_app_message,
                                           const void *request, size_t request_size,
                                           void *response,
                                           size_t *response_size)
{
    libspdm_return_t status;
    libspdm_context_t *context;
    spdm_message_header_t *spdm_request;
    size_t spdm_request_size;
    spdm_error_response_t *spdm_response;
    size_t spdm_response_size;
    uint8_t *message;
    size_t message_size;
    size_t transport_header_size;

    context = spdm_context;
    spdm_response = response;

    transport_header_size = context->transport_get_header_size(context);
    status = libspdm_acquire_sender_buffer (context, &message_size, (void **)&message);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_ASSERT (message_size >= transport_header_size);
    spdm_request = (void *)(message + transport_header_size);
    spdm_request_size = message_size - transport_header_size;
    libspdm_copy_mem (spdm_request, spdm_request_size, request, request_size);
    spdm_request_size = request_size;

    status = libspdm_send_request(context, session_id, is_app_message,
                                  spdm_request_size, spdm_request);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_release_sender_buffer (context);
        return status;
    }
    libspdm_release_sender_buffer (context);

    /* receive */

    status = libspdm_acquire_receiver_buffer (context, &message_size, (void **)&message);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_ASSERT (message_size >= transport_header_size);
    spdm_response = (void *)(message);
    spdm_response_size = message_size;

    status = libspdm_receive_response(context, session_id, is_app_message,
                                      &spdm_response_size, (void **)&spdm_response);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_release_receiver_buffer (context);
        return status;
    }

    if (spdm_response->header.request_response_code == SPDM_ERROR) {
        if ((spdm_response->header.param1 == SPDM_ERROR_CODE_DECRYPT_ERROR) &&
            (session_id != NULL)) {
            libspdm_free_session_id(context, *session_id);
            libspdm_release_receiver_buffer (context);
            return LIBSPDM_STATUS_SESSION_MSG_ERROR;
        }
    }

    if (*response_size >= spdm_response_size) {
        libspdm_copy_mem (response, *response_size, spdm_response, spdm_response_size);
        *response_size = spdm_response_size;
    } else {
        *response_size = spdm_response_size;
        libspdm_release_receiver_buffer (context);
        return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
    }

    libspdm_release_receiver_buffer (context);

    return LIBSPDM_STATUS_SUCCESS;
}
