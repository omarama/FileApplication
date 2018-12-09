#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_AuditLoggingEnc_sample_t {
	sgx_status_t ms_retval;
	char* ms_plain;
	int ms_length;
	char* ms_cipher;
	int ms_lengthOutput;
	char* ms_filename;
	int ms_lengthFilename;
} ms_ecall_AuditLoggingEnc_sample_t;

typedef struct ms_ecall_AuditLoggingDec_sample_t {
	sgx_status_t ms_retval;
	char* ms_cipher;
	int ms_length;
	char* ms_plain;
	int ms_lengthOutput;
	char* ms_filename;
	int ms_lengthFilename;
} ms_ecall_AuditLoggingDec_sample_t;

typedef struct ms_sgx_ra_get_ga_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	sgx_ec256_public_t* ms_g_a;
} ms_sgx_ra_get_ga_t;

typedef struct ms_sgx_ra_proc_msg2_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	sgx_ra_msg2_t* ms_p_msg2;
	sgx_target_info_t* ms_p_qe_target;
	sgx_report_t* ms_p_report;
	sgx_quote_nonce_t* ms_p_nonce;
} ms_sgx_ra_proc_msg2_trusted_t;

typedef struct ms_sgx_ra_get_msg3_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint32_t ms_quote_size;
	sgx_report_t* ms_qe_report;
	sgx_ra_msg3_t* ms_p_msg3;
	uint32_t ms_msg3_size;
} ms_sgx_ra_get_msg3_trusted_t;

typedef struct ms_ocall_print_string_t {
	char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_get_binary_t {
	char* ms_text;
	int ms_textLength;
	char* ms_fileName;
	int ms_fileNameSize;
} ms_ocall_get_binary_t;

typedef struct ms_ocall_write_binary_t {
	char* ms_text;
	int ms_textLength;
	char* ms_fileName;
	int ms_fileNameSize;
} ms_ocall_write_binary_t;

typedef struct ms_ocall_get_binary_file_size_t {
	char* ms_path;
	int ms_pathLength;
	int* ms_size;
} ms_ocall_get_binary_file_size_t;

typedef struct ms_ocall_get_timestamp_t {
	long int ms_retval;
} ms_ocall_get_timestamp_t;

typedef struct ms_ocall_send_via_socket_t {
	int ms_retval;
	char* ms_sendBuf;
	int ms_length;
} ms_ocall_send_via_socket_t;

typedef struct ms_ocall_receive_from_socket_t {
	int ms_retval;
	char* ms_recvBuf;
	int ms_length;
} ms_ocall_receive_from_socket_t;

typedef struct ms_create_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t* ms_sid;
	uint8_t* ms_dh_msg1;
	uint32_t ms_dh_msg1_size;
	uint32_t ms_timeout;
} ms_create_session_ocall_t;

typedef struct ms_exchange_report_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint8_t* ms_dh_msg2;
	uint32_t ms_dh_msg2_size;
	uint8_t* ms_dh_msg3;
	uint32_t ms_dh_msg3_size;
	uint32_t ms_timeout;
} ms_exchange_report_ocall_t;

typedef struct ms_close_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint32_t ms_timeout;
} ms_close_session_ocall_t;

typedef struct ms_invoke_service_ocall_t {
	sgx_status_t ms_retval;
	uint8_t* ms_pse_message_req;
	uint32_t ms_pse_message_req_size;
	uint8_t* ms_pse_message_resp;
	uint32_t ms_pse_message_resp_size;
	uint32_t ms_timeout;
} ms_invoke_service_ocall_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	void* ms_waiter;
	void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_get_binary(void* pms)
{
	ms_ocall_get_binary_t* ms = SGX_CAST(ms_ocall_get_binary_t*, pms);
	ocall_get_binary(ms->ms_text, ms->ms_textLength, (const char*)ms->ms_fileName, ms->ms_fileNameSize);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_write_binary(void* pms)
{
	ms_ocall_write_binary_t* ms = SGX_CAST(ms_ocall_write_binary_t*, pms);
	ocall_write_binary(ms->ms_text, ms->ms_textLength, (const char*)ms->ms_fileName, ms->ms_fileNameSize);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_get_binary_file_size(void* pms)
{
	ms_ocall_get_binary_file_size_t* ms = SGX_CAST(ms_ocall_get_binary_file_size_t*, pms);
	ocall_get_binary_file_size((const char*)ms->ms_path, ms->ms_pathLength, ms->ms_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_get_timestamp(void* pms)
{
	ms_ocall_get_timestamp_t* ms = SGX_CAST(ms_ocall_get_timestamp_t*, pms);
	ms->ms_retval = ocall_get_timestamp();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_send_via_socket(void* pms)
{
	ms_ocall_send_via_socket_t* ms = SGX_CAST(ms_ocall_send_via_socket_t*, pms);
	ms->ms_retval = ocall_send_via_socket((const char*)ms->ms_sendBuf, ms->ms_length);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_receive_from_socket(void* pms)
{
	ms_ocall_receive_from_socket_t* ms = SGX_CAST(ms_ocall_receive_from_socket_t*, pms);
	ms->ms_retval = ocall_receive_from_socket(ms->ms_recvBuf, ms->ms_length);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_create_session_ocall(void* pms)
{
	ms_create_session_ocall_t* ms = SGX_CAST(ms_create_session_ocall_t*, pms);
	ms->ms_retval = create_session_ocall(ms->ms_sid, ms->ms_dh_msg1, ms->ms_dh_msg1_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_exchange_report_ocall(void* pms)
{
	ms_exchange_report_ocall_t* ms = SGX_CAST(ms_exchange_report_ocall_t*, pms);
	ms->ms_retval = exchange_report_ocall(ms->ms_sid, ms->ms_dh_msg2, ms->ms_dh_msg2_size, ms->ms_dh_msg3, ms->ms_dh_msg3_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_close_session_ocall(void* pms)
{
	ms_close_session_ocall_t* ms = SGX_CAST(ms_close_session_ocall_t*, pms);
	ms->ms_retval = close_session_ocall(ms->ms_sid, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_invoke_service_ocall(void* pms)
{
	ms_invoke_service_ocall_t* ms = SGX_CAST(ms_invoke_service_ocall_t*, pms);
	ms->ms_retval = invoke_service_ocall(ms->ms_pse_message_req, ms->ms_pse_message_req_size, ms->ms_pse_message_resp, ms->ms_pse_message_resp_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall((const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall((const void*)ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall((const void*)ms->ms_waiter, (const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall((const void**)ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * func_addr[16];
} ocall_table_Enclave = {
	16,
	{
		(void*)(uintptr_t)Enclave_ocall_print_string,
		(void*)(uintptr_t)Enclave_ocall_get_binary,
		(void*)(uintptr_t)Enclave_ocall_write_binary,
		(void*)(uintptr_t)Enclave_ocall_get_binary_file_size,
		(void*)(uintptr_t)Enclave_ocall_get_timestamp,
		(void*)(uintptr_t)Enclave_ocall_send_via_socket,
		(void*)(uintptr_t)Enclave_ocall_receive_from_socket,
		(void*)(uintptr_t)Enclave_create_session_ocall,
		(void*)(uintptr_t)Enclave_exchange_report_ocall,
		(void*)(uintptr_t)Enclave_close_session_ocall,
		(void*)(uintptr_t)Enclave_invoke_service_ocall,
		(void*)(uintptr_t)Enclave_sgx_oc_cpuidex,
		(void*)(uintptr_t)Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)(uintptr_t)Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)(uintptr_t)Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)(uintptr_t)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};

sgx_status_t ecall_AuditLoggingEnc_sample(sgx_enclave_id_t eid, sgx_status_t* retval, const char* plain, int length, char* cipher, int lengthOutput, const char* filename, int lengthFilename)
{
	sgx_status_t status;
	ms_ecall_AuditLoggingEnc_sample_t ms;
	ms.ms_plain = (char*)plain;
	ms.ms_length = length;
	ms.ms_cipher = cipher;
	ms.ms_lengthOutput = lengthOutput;
	ms.ms_filename = (char*)filename;
	ms.ms_lengthFilename = lengthFilename;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_AuditLoggingDec_sample(sgx_enclave_id_t eid, sgx_status_t* retval, char* cipher, int length, char* plain, int lengthOutput, const char* filename, int lengthFilename)
{
	sgx_status_t status;
	ms_ecall_AuditLoggingDec_sample_t ms;
	ms.ms_cipher = cipher;
	ms.ms_length = length;
	ms.ms_plain = plain;
	ms.ms_lengthOutput = lengthOutput;
	ms.ms_filename = (char*)filename;
	ms.ms_lengthFilename = lengthFilename;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_get_ga(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, sgx_ec256_public_t* g_a)
{
	sgx_status_t status;
	ms_sgx_ra_get_ga_t ms;
	ms.ms_context = context;
	ms.ms_g_a = g_a;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_proc_msg2_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce)
{
	sgx_status_t status;
	ms_sgx_ra_proc_msg2_trusted_t ms;
	ms.ms_context = context;
	ms.ms_p_msg2 = (sgx_ra_msg2_t*)p_msg2;
	ms.ms_p_qe_target = (sgx_target_info_t*)p_qe_target;
	ms.ms_p_report = p_report;
	ms.ms_p_nonce = p_nonce;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_get_msg3_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size)
{
	sgx_status_t status;
	ms_sgx_ra_get_msg3_trusted_t ms;
	ms.ms_context = context;
	ms.ms_quote_size = quote_size;
	ms.ms_qe_report = qe_report;
	ms.ms_p_msg3 = p_msg3;
	ms.ms_msg3_size = msg3_size;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

