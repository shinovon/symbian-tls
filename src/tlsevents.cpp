/**
 * Copyright (c) 2024-2026 Arman Jussupgaliyev
 * Copyright (c) 2009 Nokia Corporation
 */

#include "tlsevents.h"
#include "mbedcontext.h"
#include "LOGFILE.h"
#include "tlsconnection.h"

// callbacks for mbedtls

LOCAL_C int send_callback(void *ctx, const unsigned char *buf, size_t len)
{
	CBio* s = (CBio*) ctx;
	LOG(Log::Printf(_L("+send_callback %d state: %d"), len, s->iWriteState));
	
	if (s->iWriteState == 1) {
		if (s->iWriteLength != len) {
			// TODO do partial copy?
			LOG(Log::Printf(_L("writelength different! %d != "), len, s->iWriteLength));
		}
		s->iWriteState = 0;
		LOG(Log::Printf(_L("-send_callback %d"), len));
		return len;
	}
	if (s->iWriteState == 0) {
		s->iWritePtr = (const TUint8*) buf;
		s->iWriteLength = len;
		s->iWriteState = 2;
		LOG(Log::Printf(_L("-send_callback WANT_WRITE %d"), len));
		return MBEDTLS_ERR_SSL_WANT_WRITE;
	}
	s->iWriteState = 0;
	
	const TPtrC8 des((const TUint8*) buf, len);
	
	TRequestStatus stat;
#ifdef USE_GENERIC_SOCKET
	if (s->iIsGenericSocket) {
		s->iGenericSocket.Send(des, 0, stat);
	} else
#endif
	{
		s->iSocket.Send(des, 0, stat);
	}
	User::WaitForRequest(stat);
	
	TInt ret = stat.Int() != KErrNone ? stat.Int() : len;
	LOG(Log::Printf(_L("-send_callback SYNC %d (%d)"), ret, stat.Int()));
	return ret;
}

LOCAL_C int recv_callback(void *ctx, unsigned char *buf, size_t len)
{
//	LOG(Log::Printf(_L("+recv_callback %d"), len));
	CBio* s = (CBio*) ctx;
	LOG(Log::Printf(_L("+recv_callback: %d state: %d"), len, s->iReadState));
	
	TPtr8 des = TPtr8(buf, 0, len);
	
	if (s->iReadState == 1) {
		// TODO check for overflow
		if (s->iPtrHBuf.Length() > len) {
			User::Panic(_L("newtls"), 1);
			return 0;
		}
		if (s->iPtrHBuf.Length() == 0) {
			return MBEDTLS_ERR_SSL_WANT_READ;
		}
		des.Copy(s->iPtrHBuf);
		s->iReadState = 0;
		LOG(Log::Printf(_L("-recv_callback %d"), s->iPtrHBuf.Length()));
		return s->iPtrHBuf.Length();
	}
	
	if (s->iReadState == 0) {
		s->iReadLength = (TInt) len;
		s->iReadState = 2;
		LOG(Log::Printf(_L("-recv_callback WANT_READ %d"), len));
		return MBEDTLS_ERR_SSL_WANT_READ;
	}
	
	s->iReadLength = -1;
	
	TRequestStatus stat;
#ifdef USE_GENERIC_SOCKET
	if (s->iIsGenericSocket) {
		s->iGenericSocket.Recv(des, 0, stat);
	} else
#endif
	{
		s->iSocket.RecvOneOrMore(des, 0, stat, s->iRecvLen);
	}
	User::WaitForRequest(stat);
	
	TInt ret = stat.Int() != KErrNone ? stat.Int() : des.Length();
	if (ret == KErrEof) ret = 0;
	LOG(Log::Printf(_L("-recv_callback SYNC %d (%d)"), ret, stat.Int()));
	return ret;
}

//

CBio* CBio::NewL(CTlsConnection& aTlsConnection)
{
	CBio* self = new(ELeave) CBio(aTlsConnection);
	CleanupStack::PushL(self);
	self->ConstructL(aTlsConnection);
	CleanupStack::Pop();
	return self;
}

CBio::CBio(CTlsConnection& aTlsConnection) :
  iTlsConnection(aTlsConnection),
#ifdef USE_GENERIC_SOCKET
  iGenericSocket(*aTlsConnection.iGenericSocket),
  iIsGenericSocket(aTlsConnection.iIsGenericSocket),
#endif
  iSocket(*aTlsConnection.iSocket),
  iPtrHBuf(0, 0),
  iReadState(0),
  iReadLength(-1),
  iWriteState(0)
{
	aTlsConnection.MbedContext().SetBio(this, (TAny*) send_callback, (TAny*) recv_callback, NULL);
}

void CBio::ConstructL(CTlsConnection& aTlsConnection)
{
	if (!iDataIn) {
		iDataIn = HBufC8::NewL(0x1000);
	}
}

CBio::~CBio()
{
	LOG(Log::Printf(_L("~CBio()")));
	delete iDataIn;
}

void CBio::Recv(TRequestStatus* aStatus)
{
	if (iReadState == 1) {
		User::RequestComplete(aStatus, KErrNone);
		return;
	}
	TInt len = iReadLength;
	if (len == -1) {
		// default to header size
		len = 5;
	}
	LOG(Log::Printf(_L("+CBio::Recv %d"), len));
	
	if (iReadLength > iDataIn->Des().MaxLength()) {
		// grow buffer
		LOG(Log::Printf(_L("Reconstructing input buffer")));
		delete iDataIn;
		iDataIn = NULL;
		iDataIn = HBufC8::NewL(iReadLength);
		if (!iDataIn) {
			User::RequestComplete(aStatus, KErrNoMemory);
			return;
		}
	}
	iPtrHBuf.Set((TUint8*)iDataIn->Des().Ptr(), 0, len);
#ifdef USE_GENERIC_SOCKET
	if (iIsGenericSocket) {
		iGenericSocket.Recv(iPtrHBuf, 0, *aStatus);
	} else
#endif
	{
		iSocket.RecvOneOrMore(iPtrHBuf, 0, *aStatus, iRecvLen);
	}

	iReadState = 1;
	iReadLength = -1;
	LOG(Log::Printf(_L("-CBio::Recv")));
}

void CBio::Send(TRequestStatus* aStatus)
{
	if (iWriteState == 1 || !iWritePtr) {
		// should not happen
		User::RequestComplete(aStatus, KErrNone);
		return;
	}
//	LOG(Log::Printf(_L("CBio::Send %d"), iWriteLength));
	iWriteDes.Set((const TUint8*) iWritePtr, iWriteLength);
#ifdef USE_GENERIC_SOCKET
	if (iIsGenericSocket) {
		iGenericSocket.Send(iWriteDes, 0, *aStatus);
	} else
#endif
	{
		iSocket.Send(iWriteDes, 0, *aStatus);
	}
	iWriteState = 1;
	iWritePtr = NULL;
}

void CBio::ClearRecvBuffer()
{
	LOG(Log::Printf(_L("CRecvEvent::ClearRecvBuffer()")));
	iReadState = 0;
}

void CBio::ClearSendBuffer()
{
	LOG(Log::Printf(_L("CRecvEvent::ClearSendBuffer()")));
	iWritePtr = NULL;
	iWriteState = 0;
}

// recvdata

CRecvData* CRecvData::NewL(CTlsConnection& aTlsConnection)
{
	CRecvData* self = new(ELeave) CRecvData(aTlsConnection);
	CleanupStack::PushL(self);
	self->ConstructL(aTlsConnection);
	CleanupStack::Pop();
	return self;
}

CRecvData::CRecvData(CTlsConnection& aTlsConnection) :
  iTlsConnection(aTlsConnection),
  iRecvEvent(aTlsConnection.RecvEvent())
{
	
}

CRecvData::~CRecvData()
{
	LOG(Log::Printf(_L("CRecvData::~CRecvData")));
	SetSockXfrLength(NULL);
	Cancel(KErrNone);
}

void CRecvData::ConstructL(CTlsConnection& aTlsConnection)
{
	LOG(Log::Printf(_L("CRecvData::ConstructL()")));
	Resume();
}

void CRecvData::Suspend()
{
	LOG(Log::Printf(_L("CRecvData::Suspend()")));
	iUserData = iRecvEvent.UserData();
	iRecvEvent.SetUserData(NULL);
}

void CRecvData::Resume()
{
	LOG(Log::Printf(_L("CRecvData::Resume()")));
	iRecvEvent.SetUserData(iUserData);
	iRecvEvent.SetUserMaxLength(iUserData ? iUserData->MaxLength() : 0);
	iRecvEvent.ReConstruct(this);
	
	if (!iActiveEvent) {
		iActiveEvent = &iRecvEvent;
	}
}

void CRecvData::OnCompletion()
{
	LOG(Log::Printf(_L("CRecvData::OnCompletion() %d %d"), iLastError, iStatus.Int()));
	if (iLastError == KErrNone && iStatus.Int() == KErrNone) {
		TDes8* pData = iRecvEvent.UserData();
		if (pData) {
			if (iSockXfrLength && pData->Length()) {
				LOG(Log::Printf(_L("xfr set %d"), pData->Length()));
				*iSockXfrLength = pData->Length();
			}
			else if (pData->Length() < pData->MaxLength()) {
				LOG(Log::Printf(_L("Recvdata repeat %d / %d"), pData->Length(), pData->MaxLength()));
				iActiveEvent = &iRecvEvent;
				Start(iClientStatus, iStateMachineNotify);
				return;
			}
		}
	}
	
	LOG(Log::Printf(_L("Recvdata complete")));
	
	iRecvEvent.SetUserData(NULL);
	iRecvEvent.SetUserMaxLength(0);
	
	if (iStatus.Int() == KRequestPending) {
		TRequestStatus* p = &iStatus;
		User::RequestComplete(p, iLastError);
	}
	
	CStateMachine::OnCompletion();
}

void CRecvData::DoCancel()
{
	LOG(Log::Printf(_L("CRecvData::DoCancel()")));
	iLastError = KErrCancel;
	iRecvEvent.CancelAll();
	CStateMachine::DoCancel();
}

// recvevent

CRecvEvent::CRecvEvent(CMbedContext& aMbedContext, CBio& aBio) :
  CAsynchEvent(0),
  iMbedContext(aMbedContext),
  iBio(aBio)
{
}

CRecvEvent::~CRecvEvent()
{
	LOG(Log::Printf(_L("CRecvEvent::~CRecvEvent()")));
}

void CRecvEvent::CancelAll()
{
	LOG(Log::Printf(_L("CRecvEvent::CancelAll()")));
	iBio.ClearRecvBuffer();
}

void CRecvEvent::ReConstruct(CStateMachine* aStateMachine)
{
	iStateMachine = aStateMachine;
}

LOCAL_C TInt MapError(TInt aErr, TInt aDefault) {
	switch (aErr) {
#ifdef BEARSSL
		case -BR_ERR_BAD_MAC:
			return KErrSSLBadMAC;
		case -BR_ERR_UNEXPECTED:
			return KErrSSLUnexpectedMessage;
		case -BR_ERR_BAD_VERSION:
			return KErrSSLBadProtocolVersion;
		case -BR_ERR_BAD_HANDSHAKE:
			return KErrSSLAlertHandshakeFailure;
#else
		case MBEDTLS_ERR_SSL_INVALID_MAC:
			return KErrSSLBadMAC;
		case MBEDTLS_ERR_SSL_INVALID_RECORD:
//		case MBEDTLS_ERR_SSL_DECODE_ERROR:
			return KErrSSLBadRecordHeader;
		case MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE:
			return KErrSSLNoClientCert;
		case MBEDTLS_ERR_SSL_UNSUPPORTED_EXTENSION:
			return KErrSSLRecvNotSupportedHS;
		case MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE:
			return KErrSSLUnexpectedMessage;
		case MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE:
			return KErrSSLReceivedAlert;
		case MBEDTLS_ERR_SSL_BAD_CERTIFICATE:
			return KErrSSLInvalidCert;
		case MBEDTLS_ERR_SSL_CONN_EOF:
		case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
			return KErrEof;
		case MBEDTLS_ERR_SSL_TIMEOUT:
			return KErrTimedOut;
		case MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION:
			return KErrSSLBadProtocolVersion;
		case MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE:
			return KErrSSLAlertHandshakeFailure;
#endif
		default:
#ifdef BEARSSL
//			if (aErr <= -BR_ERR_RECV_FATAL_ALERT && aErr > -(BR_ERR_RECV_FATAL_ALERT + 256)) {
//				return KErrSSLReceivedAlert;
//			}
			if (aErr == MBEDTLS_ERR_SSL_CONN_EOF) return KErrEof;
#endif
			return aDefault;
	}
}

CAsynchEvent* CRecvEvent::ProcessL(TRequestStatus& aStatus)
{
	LOG(Log::Printf(_L("+CRecvEvent::ProcessL()")));
	TRequestStatus* pStatus = &aStatus;
	
	TInt ret = iStateMachine->LastError();
	if (ret != KErrNone) {
		LOG(Log::Printf(_L("-CRecvEvent::ProcessL() Err")));
		User::RequestComplete(pStatus, iStateMachine->LastError());
		return NULL;
	}
	if (/*iBio.iReadState == 0 || */iBio.iReadState == 2) {
		iBio.Recv(&aStatus);
		return this;
	}
	if (iBio.iWriteState == 2) {
		iBio.Send(&aStatus);
		return this;
	}
	TInt offset = iUserData->Length();
	TInt res = iMbedContext.Read((unsigned char*) iUserData->Ptr() + offset, iUserMaxLength - offset);
//	if (res == MBEDTLS_ERR_SSL_WANT_READ) {
//		iBio.Recv(&aStatus);
//		return this;
//	}
//	if (res == MBEDTLS_ERR_SSL_WANT_WRITE) {
//		iBio.Send(&aStatus);
//		return this;
//	}
	if (res == MBEDTLS_ERR_SSL_WANT_READ || res == MBEDTLS_ERR_SSL_WANT_WRITE) {
		User::RequestComplete(pStatus, KErrNone);
		return this;
	}
	if (res == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
		// this return code is specific mbedtls 3.4.1 version
		// TODO: handle it?
		LOG(Log::Printf(_L("Ticket received on read")));
		User::RequestComplete(pStatus, KErrNone);
		return this;
	}
	if (res == 0 || res == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || res == MBEDTLS_ERR_SSL_CONN_EOF) {
		ret = KErrEof;
		LOG(Log::Printf(_L("Read eof")));
	} else if (res < 0) {
		ret = MapError(res, res);
		LOG(Log::Printf(_L("Read error: %x"), -res));
	} else {
		LOG(Log::Printf(_L("Recv %d"), res));

		if (offset + res > iUserData->MaxLength()) {
			User::Panic(_L("newtls"), 2);
		}
		iUserData->SetLength(offset + res);
	}

	LOG(Log::Printf(_L("-CRecvEvent::ProcessL() Complete")));
	User::RequestComplete(pStatus, ret);
	return NULL;
}

// senddata

CSendData* CSendData::NewL(CTlsConnection& aTlsConnection)
{
	CSendData* self = new(ELeave) CSendData(aTlsConnection);
	CleanupStack::PushL(self);
	self->ConstructL(aTlsConnection);
	CleanupStack::Pop();
	return self;
}

CSendData::CSendData(CTlsConnection& aTlsConnection) :
  iTlsConnection(aTlsConnection),
  iSendEvent(aTlsConnection.SendEvent())
{
	
}

CSendData::~CSendData()
{
	LOG(Log::Printf(_L("CSendData::~CSendData")));
	SetSockXfrLength( NULL );
	Cancel(KErrNone);
}

void CSendData::ConstructL(CTlsConnection& aTlsConnection)
{
	LOG(Log::Printf(_L("CSendData::ConstructL()")));
	Resume();
}

void CSendData::Suspend()
{
	LOG(Log::Printf(_L("CSendData::Suspend()")));
	iCurrentPos = iSendEvent.CurrentPos();
	iSendEvent.SetUserData(NULL);
}

void CSendData::Resume()
{
	LOG(Log::Printf(_L("CSendData::Resume()")));
	iSendEvent.SetUserData(iUserData);
	iSendEvent.ReConstruct(this, iCurrentPos);
	iCurrentPos = 0;
	
	if (!iActiveEvent) {
		iActiveEvent = &iSendEvent;
	}
}

void CSendData::SetSockXfrLength(TInt* aLen)
{
	iSockXfrLength = aLen;
	if (iSockXfrLength) {
		*iSockXfrLength = 0;
	}
}

void CSendData::OnCompletion()
{
	LOG(Log::Printf(_L("CSendData::OnCompletion()")));
	
	TDesC8* pAppData = iSendEvent.UserData();
	if (pAppData) {
		if (iSockXfrLength && iLastError == KErrNone) {
			*iSockXfrLength = iSendEvent.CurrentPos();
		}
		if (iLastError == KErrNone && iStatus.Int() == KErrNone) {
			if (pAppData->Length() > iSendEvent.CurrentPos()) {
//				LOG(Log::Printf(_L("Senddata repeat %d / %d"), pAppData->Length(), iSendEvent.CurrentPos()));
				iActiveEvent = &iSendEvent;
				Start(iClientStatus, iStateMachineNotify);
				return;
			}
		}
	}
//	LOG(Log::Printf(_L("Senddata complete")));
	
	iSendEvent.SetUserData(NULL);
	iSendEvent.ResetCurrentPos();
	
	if (iStatus.Int() == KRequestPending) {
		TRequestStatus* p = &iStatus;
		User::RequestComplete(p, iLastError);
	}
	
	CStateMachine::OnCompletion();
}

void CSendData::DoCancel()
{
	LOG(Log::Printf(_L("CSendData::DoCancel()")));
	iLastError = KErrCancel;
	iSendEvent.CancelAll();
	CStateMachine::DoCancel();
}

// sendevent

CSendEvent::CSendEvent(CMbedContext& aMbedContext, CBio& aBio) :
  CAsynchEvent(0),
  iMbedContext(aMbedContext),
  iBio(aBio)
{
}

CSendEvent::~CSendEvent()
{
	LOG(Log::Printf(_L("CSendData::~CSendEvent")));
}

void CSendEvent::ReConstruct(CStateMachine* aStateMachine, TInt aCurrentPos)
{
	iStateMachine = aStateMachine;
	iCurrentPos = aCurrentPos;
}

void CSendEvent::CancelAll()
{
	iBio.ClearSendBuffer();
}

CAsynchEvent* CSendEvent::ProcessL(TRequestStatus& aStatus)
{
	LOG(Log::Printf(_L("+CSendEvent::ProcessL()")));
	TRequestStatus* pStatus = &aStatus;
	TInt ret = KErrNone;
	if (iStateMachine->LastError() != KErrNone) {
		User::RequestComplete(pStatus, iStateMachine->LastError());
		return NULL;
	}
	if (iBio.iWriteState == 2) {
		iBio.Send(&aStatus);
		return this;
	}
	if (iData && iCurrentPos != iData->Length()) {
		TInt res = iMbedContext.Write(iData->Ptr() + iCurrentPos, iData->Length() - iCurrentPos);

		LOG(Log::Printf(_L("Write res %d"), res));
		if (res == MBEDTLS_ERR_SSL_WANT_READ) {
			iBio.Recv(&aStatus);
			return this;
		}
		if (res == MBEDTLS_ERR_SSL_WANT_WRITE) {
			iBio.Send(&aStatus);
			return this;
		}
#ifdef BEARSSL
		if (iBio.iWriteState == 2) {
			iCurrentPos += res;
			iBio.Send(&aStatus);
			return this;
		}
#endif
		if (res == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS ||
			res == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS || 
			res == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
			User::RequestComplete(pStatus, KErrNone);
			return this;
		}
		if (res < 0) {
			ret = MapError(res, res);
			LOG(Log::Printf(_L("Write error: %x"), -res));
		} else {
			iCurrentPos += res;
		}
	}
	
	User::RequestComplete(pStatus, ret);
	return NULL;
}

// handshake

CHandshake* CHandshake::NewL(CTlsConnection& aTlsConnection)
{
	CHandshake* self = new(ELeave) CHandshake(aTlsConnection);
	CleanupStack::PushL(self);
	self->ConstructL();
	CleanupStack::Pop();
	return self;
}

CHandshake::CHandshake(CTlsConnection& aTlsConnection) :
  iTlsConnection(aTlsConnection),
  iHandshakeEvent(aTlsConnection.HandshakeEvent())
{
}

CHandshake::~CHandshake()
{
	LOG(Log::Printf(_L("CHandshake::~CHandshake()")));
}

void CHandshake::ConstructL()
{
	LOG(Log::Printf(_L("CHandshake::CHandshake()")));
	Resume();
}

void CHandshake::Resume()
{
	iHandshakeEvent.Set(this);
	
	if (!iActiveEvent) {
		iActiveEvent = &iHandshakeEvent;
	}
}

void CHandshake::OnCompletion()
{
	LOG(Log::Printf(_L("CHandshake::OnCompletion(): %d"), iLastError));
	
	if (iStatus.Int() == KRequestPending) {
		TRequestStatus* p = &iStatus;
		User::RequestComplete(p, iLastError);
	}
	
	CStateMachine::OnCompletion();
}

void CHandshake::DoCancel()
{
	LOG(Log::Printf(_L("CHandshake::DoCancel()")));
	iLastError = KErrCancel;
	iHandshakeEvent.CancelAll();
	CStateMachine::DoCancel();
}

// handshake event

CHandshakeEvent::CHandshakeEvent(CMbedContext& aMbedContext, CBio& aBio) :
  CAsynchEvent(NULL),
  iMbedContext(aMbedContext),
  iBio(aBio)
{
}

CHandshakeEvent::~CHandshakeEvent()
{
	LOG(Log::Printf(_L("CHandshakeEvent::~CHandshakeEvent()")));
#ifndef NO_VERIFY
	if (iSecurityDialog) {
		iSecurityDialog->Release();
	}
#endif
}

void CHandshakeEvent::CancelAll()
{
#ifndef NO_VERIFY
	if (iSecurityDialog) {
		iSecurityDialog->Cancel();
	}
#endif
}

CAsynchEvent* CHandshakeEvent::ProcessL(TRequestStatus& aStatus)
{
	LOG(Log::Printf(_L("+CHandshakeEvent::ProcessL()")));
	TRequestStatus* pStatus = &aStatus;
	if (iStateMachine->LastError() != KErrNone) {
		User::RequestComplete(pStatus, iStateMachine->LastError());
		return NULL;
	}
	if (iInDialog) {
		iHandshaked = ETrue;
		LOG(Log::Printf(_L("Dialog complete")));
		User::RequestComplete(pStatus, KErrNone);
		return NULL;
	}
//	if (iBio.iWriteState == 2) {
//		iBio.Send(&aStatus);
//		return this;
//	}
//	if (iBio.iReadState == 2) {
//		iBio.Recv(&aStatus);
//		return this;
//	}
	TInt res = iHandshaked ? iMbedContext.Renegotiate() : iMbedContext.Handshake();
	if (res == MBEDTLS_ERR_SSL_WANT_READ) {
		iBio.Recv(&aStatus);
		return this;
	}
	if (res == MBEDTLS_ERR_SSL_WANT_WRITE) {
		iBio.Send(&aStatus);
		return this;
	}
	if (res == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS ||
		res == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS || 
		res == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
		User::RequestComplete(pStatus, KErrNone);
		return this;
	}
	TInt ret = KErrNone;
	if (res != 0) {
		ret = MapError(res, KErrSSLAlertHandshakeFailure);
		LOG(Log::Printf(_L("CHandshakeEvent::ProcessL() Err %x"), -res));
	}
#if !defined BEARSSL
	else {
		TUint8* data = 0;
		TInt len = iMbedContext.GetPeerCert(data);
		TBool supportedCert = EFalse;
		if (len != -1) {
			TRAP_IGNORE(
				if (iBio.iTlsConnection.iServerCert) {
					delete iBio.iTlsConnection.iServerCert;
					iBio.iTlsConnection.iServerCert = NULL;
				}
				iBio.iTlsConnection.iServerCert = CX509Certificate::NewL(TPtrC8(data, len));
				supportedCert = ETrue;
			);
		}
#ifndef NO_VERIFY
		res = iMbedContext.Verify();
		LOG(Log::Printf(_L("Verify result: %d"), res));
		if (res == 0) {
			// verify successful, do nothing
		} else if (res == -1u || len == -1) {
			// mbedtls returned fatal error
			ret = KErrSSLInvalidCert;
		} else if (iMbedContext.Hostname() == NULL) {
			// no hostname set??
			ret = KErrSSLInvalidCert;
		} else if (iBio.iTlsConnection.iDialogMode == EDialogModeUnattended) {
			ret = KErrSSLInvalidCert;
		} else if (!supportedCert) {
			// TODO: custom security dialog?
			ret = KErrSSLInvalidCert;
		} else {
			iInDialog = ETrue;
			iSecurityDialog = SecurityDialogFactory::CreateL();
			iSecurityDialog->ServerAuthenticationFailure(TPtrC8(iMbedContext.Hostname()), ENotCACert, TPtrC8(data, len), aStatus);
			if (data) User::Free(data); // i hope that function called above copies it
			return this;
		}
#endif
		if (data) User::Free(data);
	}
#endif
	iHandshaked = ETrue;
	User::RequestComplete(pStatus, ret);
	return NULL;
}
