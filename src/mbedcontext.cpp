/**
 * Copyright (c) 2024-2026 Arman Jussupgaliyev
 */

#include "mbedcontext.h"
#include "LOGFILE.h"
#ifdef BEARSSL
#include <stdlib.h>
//#include "certs.h"

static TInt get_last_bearssl_error(br_ssl_engine_context* eng) {
	int err = br_ssl_engine_last_error(eng);
	if (err == BR_ERR_OK) return MBEDTLS_ERR_SSL_CONN_EOF;
	return -err;
}

static int Pump(CMbedContext* ctx, br_ssl_client_context* sc, br_sslio_context* ioc, bool allow_read) {
	unsigned initial_state = br_ssl_engine_current_state(&sc->eng);
	bool completing_handshake = !(initial_state & BR_SSL_SENDAPP);

	bool progressed = true;
	while (progressed) {
		progressed = false;
		
		while (true) {
			size_t slen = 0;
			unsigned char* sbuf = br_ssl_engine_sendrec_buf(&sc->eng, &slen);
			if (sbuf != NULL && slen > 0) {
				int r = ioc->low_write(ioc->write_context, sbuf, slen);
				if (r > 0) {
					br_ssl_engine_sendrec_ack(&sc->eng, r);
					progressed = true;
					
					if (completing_handshake && (br_ssl_engine_current_state(&sc->eng) & BR_SSL_SENDAPP)) {
						return 0; 
					}
				} else if (r == MBEDTLS_ERR_SSL_WANT_WRITE) {
					return MBEDTLS_ERR_SSL_WANT_WRITE;
				} else if (r < 0) {
					return r;
				}
			} else {
				break; 
			}
		}
		
		if (allow_read) {
			size_t rlen = 0;
			unsigned char* rbuf = br_ssl_engine_recvrec_buf(&sc->eng, &rlen);
			if (rbuf != NULL && rlen > 0) {
				int r = ioc->low_read(ioc->read_context, rbuf, rlen);
				if (r > 0) {
					br_ssl_engine_recvrec_ack(&sc->eng, r);
					progressed = true;

					if (completing_handshake && (br_ssl_engine_current_state(&sc->eng) & BR_SSL_SENDAPP)) {
						return 0; 
					}
				} else if (r == MBEDTLS_ERR_SSL_WANT_READ) {
					return MBEDTLS_ERR_SSL_WANT_READ;
				} else if (r == 0) {
					return MBEDTLS_ERR_SSL_CONN_EOF;
				} else if (r < 0) {
					return r;
				}
			}
		}
	}
	return 0;
}


static void x509_start_cert(const br_x509_class** ctx, uint32_t length) {
	br_x509_minimal_vtable.start_cert(ctx, length);
}

static void x509_append(const br_x509_class** ctx, const unsigned char* buf, size_t len) {
	br_x509_minimal_vtable.append(ctx, buf, len);
}

static void x509_end_cert(const br_x509_class** ctx) {
	br_x509_minimal_vtable.end_cert(ctx);
}

static void x509_start_chain(const br_x509_class** ctx, const char* server_name) {
	br_x509_minimal_vtable.start_chain(ctx, server_name);
}

static unsigned x509_end_chain(const br_x509_class** ctx) {
	unsigned r = br_x509_minimal_vtable.end_chain(ctx);

	return 0;
}

static const br_x509_pkey* x509_get_pkey(const br_x509_class*const* ctx, unsigned* usages) {
	return br_x509_minimal_vtable.get_pkey(ctx, usages);
}

static const br_x509_class cert_verifier_vtable = {
	sizeof(br_x509_minimal_context),
	x509_start_chain,
	x509_start_cert,
	x509_append,
	x509_end_cert,
	x509_end_chain,
	x509_get_pkey
};
#else
#include <mbedtls/debug.h>

#ifdef _DEBUG
static void my_debug(void *ctx, int level,
                     const char *file, int line,
                     const char *str)
{
//	((void) level);
	LOG(Log::Printf8(_L8("mbedtls: %s:%04d: %s"), file, line, str));
}
#endif
#endif

CMbedContext::CMbedContext()
{
#ifdef BEARSSL
	//br_ssl_client_init_full(&sc, &xc, TAs, TAs_NUM);
	br_ssl_client_init_full(&sc, &xc, NULL, 0);
	iResetDone = false;

	{
		char buf[32];
		for (int i = 0; i < 8; i++) {
			int seed = rand();
			buf[i << 2] = (unsigned char)(seed & 0xFF);
			buf[(i << 2) + 1] = (unsigned char)((seed >> 8) & 0xFF);
			buf[(i << 2) + 2] = (unsigned char)((seed >> 16) & 0xFF);
			buf[(i << 2) + 3] = (unsigned char)((seed >> 24) & 0xFF);
		}
		br_ssl_engine_inject_entropy(&sc.eng, buf, 32);
	}
	
	br_ssl_engine_set_buffer(&sc.eng, iobuf, sizeof(iobuf), 1);
#else
	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);
#endif
	hostname = NULL;
}

CMbedContext::~CMbedContext()
{
#ifndef BEARSSL
	mbedtls_ssl_free(&ssl);
	mbedtls_ssl_config_free(&conf);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	mbedtls_x509_crt_free(&cacert);
#endif
	if (hostname != NULL) {
		delete[] hostname;
		hostname = NULL;
	}
}

void CMbedContext::SetBio(TAny* aContext, TAny* aSend, TAny* aRecv, TAny* aTimeout)
{
#ifdef BEARSSL
	//ioc.engine = &sc.eng;
	ioc.read_context = aContext;
	ioc.low_read = (int (*)(void *, unsigned char *, size_t)) aRecv;
	ioc.write_context = aContext;
	ioc.low_write = (int (*)(void *, const unsigned char *, size_t)) aSend;
#else
	mbedtls_ssl_set_bio(&ssl,
		aContext,
		(mbedtls_ssl_send_t *) aSend,
		(mbedtls_ssl_recv_t *) aRecv,
		(mbedtls_ssl_recv_timeout_t *) aTimeout);
#endif
}

TInt CMbedContext::InitSsl()
{
	TInt ret(0);
	
#ifdef BEARSSL
	br_ssl_engine_set_versions(&sc.eng, BR_TLS10, BR_TLS12);
#else
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
#endif
	
	exit:
	return ret;
}

void CMbedContext::SetHostname(const char* aHostname)
{
	hostname = aHostname;
#ifndef BEARSSL
	mbedtls_ssl_set_hostname(&ssl, aHostname);
#endif
}

TInt CMbedContext::Handshake()
{
#ifdef BEARSSL
	if (!iResetDone) {
		if (hostname == 0) {
			LOG(Log::Printf(_L("no hostname!")));
		}
		br_ssl_client_reset(&sc, hostname, 0);
		xc.vtable = &cert_verifier_vtable;
		iResetDone = true;
	}
	
	int r = Pump(this, &sc, &ioc, true); 
	unsigned state = br_ssl_engine_current_state(&sc.eng);
	if (r < 0) {
		LOG(Log::Printf(_L("CMbedContext::Handshake(): 2 pump: %d, state is %x"), r, state));
		return r;
	}
	
	LOG(Log::Printf(_L("CMbedContext::Handshake(): pump: %d, state is %x"), r, state));
	if (state == BR_SSL_CLOSED) {
		return get_last_bearssl_error(&sc.eng);
	}
	if ((state & BR_SSL_SENDAPP) || (state & BR_SSL_RECVAPP)) {
		return 0;
	}
	
	return MBEDTLS_ERR_SSL_WANT_READ;
	
#else
	return mbedtls_ssl_handshake(&ssl);
#endif
}

TInt CMbedContext::Renegotiate()
{
#ifdef BEARSSL
	return Handshake();
#else
	return mbedtls_ssl_renegotiate(&ssl);
#endif
}

TInt CMbedContext::GetPeerCert(TUint8*& aData) {
#ifdef BEARSSL
	return -1;
#else
	const mbedtls_x509_crt* cert = mbedtls_ssl_get_peer_cert(&ssl);
	if (!cert) {
		return -1;
	}
	size_t len = cert->raw.len;
	aData = (TUint8*) User::Alloc(len);
	memcpy(aData, cert->raw.p, len);
	
	return len;
#endif
}

TInt CMbedContext::Verify()
{
#ifdef BEARSSL
	return 0;
#else
	return mbedtls_ssl_get_verify_result(&ssl);
#endif
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
#ifdef BEARSSL
	
	int r = Pump(this, &sc, &ioc, true); 
		
	unsigned state = br_ssl_engine_current_state(&sc.eng);
	if (state == BR_SSL_CLOSED) {
		int err = br_ssl_engine_last_error(&sc.eng);
		if (err == BR_ERR_OK) return MBEDTLS_ERR_SSL_CONN_EOF;
		return -err;
	}
	
	size_t rlen;
	unsigned char* rbuf = br_ssl_engine_recvapp_buf(&sc.eng, &rlen);
	if (rbuf != NULL && rlen > 0) {
		if (rlen > (size_t)aLen) rlen = aLen;
		memcpy(aData, rbuf, rlen);
		br_ssl_engine_recvapp_ack(&sc.eng, rlen);
		return rlen;
	}
	
	if (r < 0) return r;
	return MBEDTLS_ERR_SSL_WANT_READ;
#else
	return mbedtls_ssl_read(&ssl, aData, static_cast<unsigned int>(aLen));
#endif
}

TInt CMbedContext::Write(const unsigned char* aData, TInt aLen)
{
#ifdef BEARSSL
   int r = Pump(this, &sc, &ioc, false);
   if (r < 0) return r;

	unsigned state = br_ssl_engine_current_state(&sc.eng);
	if (state == BR_SSL_CLOSED) {
		return get_last_bearssl_error(&sc.eng);
	}
	
	size_t wlen = 0;
	unsigned char* wbuf = br_ssl_engine_sendapp_buf(&sc.eng, &wlen);
	if (wbuf != NULL && wlen > 0) {
		if (wlen > (size_t)aLen) wlen = aLen;
		memcpy(wbuf, aData, wlen);
		br_ssl_engine_sendapp_ack(&sc.eng, wlen);
		br_ssl_engine_flush(&sc.eng, 0);

		Pump(this, &sc, &ioc, false);
		return wlen;
	}
	
	return MBEDTLS_ERR_SSL_WANT_WRITE;
#else
	return mbedtls_ssl_write(&ssl, aData, static_cast<unsigned int>(aLen));
#endif
}

TInt CMbedContext::SslCloseNotify()
{
#ifdef BEARSSL
	br_ssl_engine_close(&sc.eng);
	//Pump(this, &sc, &ioc);
	return 0;
#else
	int ret;
	do {
		ret = mbedtls_ssl_close_notify(&ssl);
	} while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
			ret == MBEDTLS_ERR_SSL_WANT_WRITE);
	return ret;
#endif
}

TInt CMbedContext::Reset() {
#ifdef BEARSSL
	//br_ssl_client_reset(&sc, hostname, 1);
	return 0;
#else
	return mbedtls_ssl_session_reset(&ssl);
#endif
}

const TUint8* CMbedContext::Hostname() {
	return (const TUint8*) hostname;
}
