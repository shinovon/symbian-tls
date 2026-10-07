/**
 * Copyright (c) 2024-2026 Arman Jussupgaliyev
 */

#include "mbedcontext.h"
#include "LOGFILE.h"
#ifdef BEARSSL
#include <stdlib.h>
//#include "certs.h" // use `brssl -ta cacert.pem` to generate certificates

static TInt get_last_bearssl_error(br_ssl_engine_context* eng) {
	int err = br_ssl_engine_last_error(eng);
	if (err == BR_ERR_OK) return MBEDTLS_ERR_SSL_CONN_EOF;
	return -err;
}

int CMbedContext::Pump(unsigned target) {
	// copied from run_until in ssl_io.c
	for (;;) {
		unsigned state;

		state = br_ssl_engine_current_state(&sc.eng);
		if (state & BR_SSL_CLOSED) {
			return -1;
		}

		if (state & BR_SSL_SENDREC) {
			unsigned char *buf;
			size_t len;
			int wlen;

			buf = br_ssl_engine_sendrec_buf(&sc.eng, &len);
			wlen = ioc.low_write(ioc.write_context, buf, len);
			if (wlen < 0) {
				return wlen;
			}
			if (wlen > 0) {
				br_ssl_engine_sendrec_ack(&sc.eng, wlen);
			}
			continue;
		}

		if (state & target) {
			return 0;
		}

		if (state & BR_SSL_RECVAPP) {
			return -1;
		}

		if (state & BR_SSL_RECVREC) {
			unsigned char *buf;
			size_t len;
			int rlen;

			buf = br_ssl_engine_recvrec_buf(&sc.eng, &len);
			rlen = ioc.low_read(ioc.read_context, buf, len);
			if (rlen < 0) {
				return rlen;
			}
			if (rlen > 0) {
				br_ssl_engine_recvrec_ack(&sc.eng, rlen);
			}
			continue;
		}
		
		br_ssl_engine_flush(&sc.eng, 0);
	}
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
	(void) br_x509_minimal_vtable.end_chain(ctx);
	
	// deliberately ignoring certificate errors, since cacert storage is not yet implemented

	return 0;
}

static const br_x509_pkey* x509_get_pkey(const br_x509_class*const* ctx, unsigned* usages) {
	return br_x509_minimal_vtable.get_pkey(ctx, usages);
}

static int ssl_time_check_callback(void* ctx,
	uint32_t not_before_days, uint32_t not_before_secs,
	uint32_t not_after_days,  uint32_t not_after_secs) 
{
	// TODO
	return 0;
}
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
	//br_ssl_client_init_full(&sc, &xc, TAs, TAs_NUM); // uncomment if you include certs.h
	br_ssl_client_init_full(&sc, &xc, NULL, 0);
	iResetDone = false;

	br_x509_minimal_set_time_callback(&xc, NULL, ssl_time_check_callback);
	
	cert_verifier_vtable.context_size = sizeof(br_x509_minimal_context);
	cert_verifier_vtable.start_chain = x509_start_chain;
	cert_verifier_vtable.start_cert = x509_start_cert;
	cert_verifier_vtable.append = x509_append;
	cert_verifier_vtable.end_cert = x509_end_cert;
	cert_verifier_vtable.end_chain = x509_end_chain;
	cert_verifier_vtable.get_pkey = x509_get_pkey;
	
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
	char buf[32];
	TTime now;
	now.HomeTime();
	TInt64 seed64 = now.Int64();
	
	TUint32 seed1 = I64LOW(seed64) ^ User::TickCount();
	TUint32 seed2 = I64HIGH(seed64) ^ (TUint32)&buf;

	for (int i = 0; i < 8; i++) {
		seed1 = (seed1 * 1103515245) + 12345;
		seed2 = (seed2 * 1103515245) + 12345;
		((TUint32*)buf)[i] = seed1 ^ seed2;
	}
	br_ssl_engine_inject_entropy(&sc.eng, buf, 32);
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
	LOG(Log::Printf8(_L8("Set hostname: %s"), aHostname));
	hostname = aHostname;
#ifndef BEARSSL
	mbedtls_ssl_set_hostname(&ssl, aHostname);
#endif
}

void CMbedContext::SetPort(int aPort)
{
	port = aPort;
}

TInt CMbedContext::ReadSessions(TSessionRecord* aRecords) {
	FILE* f = fopen(KSessionFile, "rb");
	if (f == NULL) {
		return 0;
	}
	
	fseek(f, 0, SEEK_END);
	long len = ftell(f);
	if (len == -1) {
		fclose(f);
		return 0;
	}
	fseek(f, 0, SEEK_SET);
	
	TInt ret = 0;
	if (fread((unsigned char*)aRecords, 1, len, f) == len) {
		ret = len / sizeof(TSessionRecord);
	}
	
	fclose(f);
	return ret;
}

static bool OpenMutex(RMutex* mutex) {
	TInt err;
	do {
		err = mutex->CreateGlobal(KSessionMutexName);
		if (err == KErrAlreadyExists) {
			err = mutex->OpenGlobal(KSessionMutexName);
		}
	} while (err == KErrNotFound);
	return err == KErrNone;
}

TBool CMbedContext::LoadSession(void* aDataOut, size_t* aLen)
{
	if (!hostname || strlen(hostname) >= (size_t) MAX_HOST_LEN)
		return EFalse;

	RMutex mutex;
	if (!OpenMutex(&mutex)) return EFalse;
	mutex.Wait();
	
	time_t now = time(NULL);
	TSessionRecord* records = new TSessionRecord[MAX_SESSIONS];
	TBool ret = EFalse;
	if (records) {
		TInt n = ReadSessions(records);
		for (TInt i = 0; i < n; ++i) {
			if (strncmp(records[i].host, hostname, MAX_HOST_LEN) != 0 || records[i].port != port)
				continue;
			if (records[i].timestamp + SESSION_TIMEOUT < now || records[i].timestamp > now + SESSION_TIMEOUT)
				continue; // timed out
			if (records[i].len > MAX_SESSION_SIZE)
				break; // should not reach here, just in case
			
			*aLen = records[i].len;
			memcpy(aDataOut, records[i].data, records[i].len);
			ret = ETrue;
			break;
		}
		delete[] records;
	}
	
	mutex.Signal();
	mutex.Close();
	
	return ret;
}

void CMbedContext::SaveSession(const void* aData, size_t aLen)
{
	if (!hostname || strlen(hostname) >= (size_t) MAX_HOST_LEN || aLen > MAX_SESSION_SIZE)
		return;
	
	RMutex mutex;
	if (!OpenMutex(&mutex)) return;
	mutex.Wait();
	
	time_t now = time(NULL);
	TSessionRecord* records = new TSessionRecord[MAX_SESSIONS];
	if (records) {
		TInt num = ReadSessions(records);
		TInt res = -1;
		time_t time = 0;
		bool exact = false;
		for (TInt i = 0; i < num; ++i) {
			 if (strncmp(records[i].host, hostname, MAX_HOST_LEN) == 0 && records[i].port == port) {
				 res = i;
				 exact = true;
				 break;
			 }
			 
			 if (res == -1 || records[i].timestamp < time) {
				 res = i;
				 time = records[i].timestamp;
			 }
		}
		
		if (!exact) {
			if (res == -1) {
				res = 0;
				num++;
			} else if (time + SESSION_TIMEOUT > now && num < MAX_SESSIONS) {
				res = num++;
			}
		}

		Mem::FillZ(&records[res], sizeof(TSessionRecord));
		memcpy(records[res].host, hostname, strlen(hostname));
		records[res].port = port;
		records[res].timestamp = now;
		records[res].len = aLen;
		memcpy(records[res].data, aData, aLen);
		
#ifdef EKA2
		mkdir(KSessionDir, 0777);
#endif
		FILE* f = fopen(KSessionFile, "wb");
		if (f != NULL) {
			fwrite((const unsigned char*)records, 1, sizeof(TSessionRecord) * num, f);
			fflush(f);
			fclose(f);
		}
		delete[] records;
	}
	mutex.Signal();
	mutex.Close();
}

void CMbedContext::LoadSession()
{
#ifndef BEARSSL
	if (iFlushSession) {
		iFlushSession = false;
		return;
	}
	
	mbedtls_ssl_session session;
	mbedtls_ssl_session_init(&session);
	
	unsigned char* data = new unsigned char[MAX_SESSION_SIZE];
	if (data) {
		size_t len = 0;
		if (LoadSession(data, &len)) goto exit;
		if (mbedtls_ssl_session_load(&session, data, len) != 0) goto exit;
		mbedtls_ssl_set_session(&ssl, &session);
		exit:
		if (data) delete[] data;
	}
	mbedtls_ssl_session_free(&session);
#endif
}

void CMbedContext::SaveSession()
{
	if (iSessionSaved) return;
	iSessionSaved = true;
	
#ifdef BEARSSL
	br_ssl_session_parameters sp;
	br_ssl_engine_get_session_parameters(&sc.eng, &sp);
	if ((!iSessionLoaded || sp.session_id_len != iOfferedIdLen
		|| Mem::Compare(sp.session_id, sp.session_id_len, iOfferedId, iOfferedIdLen) != 0)
		&& sp.session_id_len > 0 && hostname && port != 0) {
		SaveSession(&sp, sizeof sp);
	}
#else
	mbedtls_ssl_session session;
	mbedtls_ssl_session_init(&session);
	if (mbedtls_ssl_get_session(&ssl, &session) == 0) {
		unsigned char* data = new unsigned char[MAX_SESSION_SIZE];
		if (data) {
			size_t len;
			if (mbedtls_ssl_session_save(&session, data, MAX_SESSION_SIZE, &len) == 0) {
				SaveSession(data, len);
			}
			delete[] data;
		}
	}
#endif
}

void CMbedContext::FlushSession() {
	iFlushSession = true;
}

TInt CMbedContext::Handshake()
{
#ifdef BEARSSL
	if (!iResetDone) {
		br_ssl_session_parameters sp;
		int resume = 0;
		if (!iFlushSession && LoadSession(&sp, NULL) && sp.session_id_len > 0) {
			br_ssl_engine_set_session_parameters(&sc.eng, &sp);
			memcpy(iOfferedId, sp.session_id, sp.session_id_len);
			iOfferedIdLen = sp.session_id_len;
			iSessionLoaded = true;
			resume = 1;
		}
		iFlushSession = false;
		br_ssl_client_reset(&sc, hostname, resume);
		xc.vtable = &cert_verifier_vtable;
		iResetDone = true;
	}
	
	int r = Pump(BR_SSL_SENDAPP | BR_SSL_RECVAPP); 
	unsigned state = br_ssl_engine_current_state(&sc.eng);
	
	LOG(Log::Printf(_L("CMbedContext::Handshake(): pump: %d, state is %x"), r, state));
	if (state == BR_SSL_CLOSED) {
		return get_last_bearssl_error(&sc.eng);
	}
	if ((state & BR_SSL_SENDAPP) || (state & BR_SSL_RECVAPP)) {
		return 0;
	}
	if (r < 0) return r;
	// should not reach here
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
	int r = Pump(BR_SSL_RECVAPP);
		
	unsigned state = br_ssl_engine_current_state(&sc.eng);
	if (state == BR_SSL_CLOSED) {
		return get_last_bearssl_error(&sc.eng);
	}
	
	if (r < 0) return r;
	
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
   int r = Pump(BR_SSL_SENDAPP);

	unsigned state = br_ssl_engine_current_state(&sc.eng);
	if (state == BR_SSL_CLOSED) {
		return get_last_bearssl_error(&sc.eng);
	}
	
	if (r < 0) return r;
	
	size_t wlen = 0;
	unsigned char* wbuf = br_ssl_engine_sendapp_buf(&sc.eng, &wlen);
	if (wbuf != NULL && wlen > 0) {
		if (wlen > (size_t)aLen) wlen = aLen;
		memcpy(wbuf, aData, wlen);
		br_ssl_engine_sendapp_ack(&sc.eng, wlen);
		br_ssl_engine_flush(&sc.eng, 0);

		Pump(BR_SSL_SENDAPP);
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
	//Pump();
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
