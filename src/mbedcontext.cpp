/**
 * Copyright (c) 2024 Arman Jussupgaliyev
 */

#include "mbedcontext.h"
#include "LOGFILE.h"
#include <mbedtls/debug.h>

CMbedContext::CMbedContext()
{
	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);
	hostname = NULL;
}

CMbedContext::~CMbedContext()
{
	mbedtls_ssl_free(&ssl);
	mbedtls_ssl_config_free(&conf);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	mbedtls_x509_crt_free(&cacert);
	if (hostname != NULL) {
		delete[] hostname;
		hostname = NULL;
	}
}

void CMbedContext::SetBio(TAny* aContext, TAny* aSend, TAny* aRecv, TAny* aTimeout)
{
	mbedtls_ssl_set_bio(&ssl,
		aContext,
		(mbedtls_ssl_send_t *) aSend,
		(mbedtls_ssl_recv_t *) aRecv,
		(mbedtls_ssl_recv_timeout_t *) aTimeout);
}

#ifdef _DEBUG
static void my_debug(void *ctx, int level,
                     const char *file, int line,
                     const char *str)
{
//	((void) level);
	LOG(Log::Printf8(_L8("mbedtls: %s:%04d: %s"), file, line, str));
}
#endif

TInt CMbedContext::InitSsl()
{
	TInt ret(0);
	
	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
									 NULL, 0)) != 0) {
		goto exit;
	}

	if ((ret = mbedtls_ssl_config_defaults(&conf,
											   MBEDTLS_SSL_IS_CLIENT,
											   MBEDTLS_SSL_TRANSPORT_STREAM,
											   MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
		goto exit;
	}
	
	
#ifdef NO_VERIFY
	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
#else
	mbedtls_x509_crt_init(&cacert);
	if ((ret = mbedtls_x509_crt_parse_path(&cacert, "C:/resource/mbedtls/cacerts/")) < 0) {
		// no cacerts dir, ignore?
		mbedtls_x509_crt_free(&cacert);
		mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
//		goto exit;
	} else {
		mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
		mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
	}
	LOG(Log::Printf(_L("crt parse %x"), ret));
#endif
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
#ifdef _DEBUG
	mbedtls_debug_set_threshold(999999);
	mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);
#endif
	mbedtls_ssl_conf_session_tickets(&conf, 0);
	mbedtls_ssl_conf_renegotiation(&conf, 0);
	
	if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
		goto exit;
	}
	
	exit:
	return ret;
}

void CMbedContext::SetHostname(const char* aHostname)
{
	hostname = aHostname;
	mbedtls_ssl_set_hostname(&ssl, aHostname);
}

TInt CMbedContext::Handshake()
{
	return mbedtls_ssl_handshake(&ssl);
}

TInt CMbedContext::Renegotiate()
{
	return mbedtls_ssl_renegotiate(&ssl);
}

TInt CMbedContext::GetPeerCert(TUint8*& aData) {
	const mbedtls_x509_crt* cert = mbedtls_ssl_get_peer_cert(&ssl);
	if (!cert) {
		return -1;
	}
	size_t len = cert->raw.len;
	aData = (TUint8*) User::Alloc(len);
	memcpy(aData, cert->raw.p, len);
	
	return len;
}

TInt CMbedContext::Verify()
{
	return mbedtls_ssl_get_verify_result(&ssl);
}

//TInt CMbedContext::ExportSession(unsigned char *aData, TInt aMaxLen, TUint* aLen) {
//    mbedtls_ssl_session exported_session;
//    mbedtls_ssl_session_init(&exported_session);
//    int ret = mbedtls_ssl_get_session(ssl, &exported_session);
//    if (ret != 0) goto exit;
//	ret = mbedtls_ssl_session_save(&exported_session, aData, static_cast<unsigned int>(aMaxLen), aLen);
//exit:
//	mbedtls_ssl_session_free(&exported_session);
//	return ret;
//}

//TInt CMbedContext::LoadSession(const unsigned char *aData, TInt aLen) {
//	return -1;
//}

TInt CMbedContext::Read(unsigned char* aData, TInt aLen)
{
	return mbedtls_ssl_read(&ssl, aData, static_cast<unsigned int>(aLen));
}

TInt CMbedContext::Write(const unsigned char* aData, TInt aLen)
{
	return mbedtls_ssl_write(&ssl, aData, static_cast<unsigned int>(aLen));
}

TInt CMbedContext::SslCloseNotify()
{
	int ret;
	do {
		ret = mbedtls_ssl_close_notify(&ssl);
	} while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
			ret == MBEDTLS_ERR_SSL_WANT_WRITE);
	return ret;
}

TInt CMbedContext::Reset() {
	return mbedtls_ssl_session_reset(&ssl);
}

const TUint8* CMbedContext::Hostname() {
	return (const TUint8*) hostname;
}
