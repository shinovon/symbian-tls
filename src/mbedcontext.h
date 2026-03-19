/**
 * Copyright (c) 2024-2026 Arman Jussupgaliyev
 */

#ifndef MBEDCONTEXT_H
#define MBEDCONTEXT_H
#include <e32base.h>

#ifdef BEARSSL
#include <bearssl_ssl.h>
#include <bearssl_x509.h>

#define MBEDTLS_ERR_SSL_WANT_READ -0x6900 // -26880
#define MBEDTLS_ERR_SSL_WANT_WRITE -0x6880 // -26752
#define MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS -0x6800
#define MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS -0x6780
#define MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET -0x6600
#define MBEDTLS_ERR_SSL_CONN_EOF -0x7280
#define MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY -0x7880

#else
#include <mbedtls/ssl.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net_sockets.h>
#endif

class CMbedContext : public CBase {
public:
	CMbedContext();
	~CMbedContext();
	
protected:
#ifdef BEARSSL
	br_x509_minimal_context xc;
	br_ssl_client_context sc;
	unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
	br_sslio_context ioc;
	bool iResetDone;
	int iLastState;
	int Pump(unsigned target);
	br_x509_class cert_verifier_vtable;
#else
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_context entropy;
	mbedtls_x509_crt cacert;
#endif
	const char* hostname; // owned

public:
	// mbedtls_ssl_set_bio
	void SetBio(TAny* aContext, TAny* aSend, TAny* aRecv, TAny* aTimeout);
	
	TInt InitSsl();

	// mbedtls_ssl_set_hostname
	void SetHostname(const char* aHostname);
	
	// mbedtls_ssl_handshake
	TInt Handshake();
	
	// mbedtls_ssl_renegotiate
	TInt Renegotiate();
	
	// mbedtls_ssl_get_peer_cert
	TInt GetPeerCert(TUint8*& aData);
	
	// mbedtls_ssl_get_verify_result
	TInt Verify();
	
//	TInt ExportSession(unsigned char *aData, TInt aMaxLen, TUint* aLen);
//	TInt LoadSession(const unsigned char *aData, TInt aLen);
	
	// mbedtls_ssl_read
	TInt Read(unsigned char* aData, TInt aLen);
	
	// mbedtls_ssl_write
	TInt Write(const unsigned char* aData, TInt aLen);
	
	// mbedtls_ssl_close_notify
	TInt SslCloseNotify();
	
	// mbedtls_ssl_session_reset
	TInt Reset();
	
	const TUint8* Hostname();
};
#endif
