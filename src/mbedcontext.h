/**
 * Copyright (c) 2024-2026 Arman Jussupgaliyev
 */

#ifndef MBEDCONTEXT_H
#define MBEDCONTEXT_H
#include <e32base.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>

#ifdef BEARSSL
#include <bearssl_ssl.h>
#include <bearssl_x509.h>

#define MBEDTLS_ERR_SSL_WANT_READ -0x6900 // -26880
#define MBEDTLS_ERR_SSL_WANT_WRITE -0x6880 // -26752
#define MBEDTLS_ERR_SSL_CONN_EOF -0x7280
#define MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY -0x7880

#define KSessionFile "C:\\system\\data\\bearssl_sessions.dat"
#else
#include <mbedtls/ssl.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net_sockets.h>

#define KSessionFile "C:\\system\\data\\mbedtls_sessions.dat"
#endif
#define KSessionDir "C:\\system\\data"

_LIT(KSessionMutexName, "TLSSessionFile");

#define MAX_SESSIONS 8
#define MAX_HOST_LEN 128
#define SESSION_TIMEOUT 86400

#ifdef BEARSSL
#define MAX_SESSION_SIZE (sizeof(br_ssl_session_parameters))
#else
#define MAX_SESSION_SIZE 1536
#endif

struct TSessionRecord {
	char host[MAX_HOST_LEN];
	int port;
	time_t timestamp;
	size_t len;
	unsigned char data[MAX_SESSION_SIZE];
};

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
	unsigned char iOfferedId[32];
	unsigned char iOfferedIdLen;
	bool iSessionLoaded;
#else
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_context entropy;
	mbedtls_x509_crt cacert;
#endif
	bool iSessionSaved;
	bool iFlushSession;
	const char* hostname; // owned
	int port;

public:
	// mbedtls_ssl_set_bio
	void SetBio(TAny* aContext, TAny* aSend, TAny* aRecv, TAny* aTimeout);
	
	TInt InitSsl();

	// mbedtls_ssl_set_hostname
	void SetHostname(const char* aHostname);
	void SetPort(int port);
	
	// mbedtls_ssl_handshake
	TInt Handshake();
	
	// mbedtls_ssl_renegotiate
	TInt Renegotiate();
	
	// mbedtls_ssl_get_peer_cert
	TInt GetPeerCert(TUint8*& aData);
	
	// mbedtls_ssl_get_verify_result
	TInt Verify();
	
	// mbedtls_ssl_read
	TInt Read(unsigned char* aData, TInt aLen);
	
	// mbedtls_ssl_write
	TInt Write(const unsigned char* aData, TInt aLen);
	
	// mbedtls_ssl_close_notify
	TInt SslCloseNotify();
	
	// mbedtls_ssl_session_reset
	TInt Reset();
	
	const TUint8* Hostname();
	
	void LoadSession();
	void SaveSession(TBool aForce=EFalse);
	void FlushSession();
private:
	static TInt ReadSessions(TSessionRecord* aRecords);
	inline TBool LoadSession(void* aDataOut, size_t* aDataLen);
	inline void SaveSession(const void* aData, size_t aLen);
};

#endif
