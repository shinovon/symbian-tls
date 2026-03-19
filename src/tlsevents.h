/**
 * Copyright (c) 2024-2026 Arman Jussupgaliyev
 * Copyright (c) 2009 Nokia Corporation
 */

#ifndef TLSEVENTS_H
#define TLSEVENTS_H

#include "statemachine.h"
#include "asynchevent.h"
#include "es_sock.h"
#ifndef NO_VERIFY
#include <secdlg.h>
#endif

class MGenericSecureSocket;
class RSocket;

class CTlsConnection;
class CMbedContext;

class CRecvEvent;
class CSendEvent;
class CHandshakeEvent;

class CBio : public CBase
{
public:
	static CBio* NewL(CTlsConnection& aTlsConnection); 
	~CBio();
	
	void Recv(TRequestStatus* aStatus);
	void Send(TRequestStatus* aStatus);
	
	void ClearRecvBuffer();
	void ClearSendBuffer();
protected:
	CBio(CTlsConnection& aTlsConnection);
	void ConstructL(CTlsConnection& aTlsConnection);
	
	HBufC8* iDataIn;
public:
	CTlsConnection& iTlsConnection;
#ifdef USE_GENERIC_SOCKET
	MGenericSecureSocket& iGenericSocket;
	TBool iIsGenericSocket;
#endif
	RSocket& iSocket;
	
	TPtr8 iPtrHBuf;
	TInt iReadState;
	TInt iReadLength;
	
	const TUint8* iWritePtr;
	TPtrC8 iWriteDes;
	TInt iWriteState;
	TInt iWriteLength;
	TSockXfrLength iRecvLen;
	
};

class CRecvData : public CStateMachine
{
public:
	static CRecvData* NewL(CTlsConnection& aTlsConnection); 
	~CRecvData();
	
	void Start(TRequestStatus* aClientStatus, MStateMachineNotify* aStateMachineNotify);
	
	void Suspend();
	void Resume();
	
	void SetSockXfrLength(TInt* aLen);

protected:
	CRecvData(CTlsConnection& aTlsConnection);
	void ConstructL(CTlsConnection& aTlsConnection);

	virtual void DoCancel();
	virtual void OnCompletion();

protected:
	CTlsConnection& iTlsConnection;
	CRecvEvent& iRecvEvent;
	
	TDes8* iUserData;
	TInt* iSockXfrLength;
};

inline void CRecvData::Start(TRequestStatus* aClientStatus, MStateMachineNotify* aStateMachineNotify)
{
	if (!iActiveEvent) {
		iActiveEvent = (CAsynchEvent *)&iRecvEvent;
	}
	CStateMachine::Start(aClientStatus, NULL, aStateMachineNotify);
}

inline void CRecvData::SetSockXfrLength(TInt* aLen)
{
	iSockXfrLength = aLen;
}



class CRecvEvent : public CAsynchEvent
{
public:
	CRecvEvent(CMbedContext& aMbedContext, CBio& aSocket);
	~CRecvEvent();
	
	virtual CAsynchEvent* ProcessL(TRequestStatus& aStatus);
	
	void SetUserData(TDes8* aData);
	void SetUserMaxLength(TInt aMaxLength);
	
	void CancelAll();
	void ReConstruct(CStateMachine* aStateMachine);
	
	TDes8* UserData();

protected:
	CMbedContext& iMbedContext;
	CBio& iBio;
	
	TDes8* iUserData;
	TInt iUserMaxLength;

protected:
	CRecvData& RecvData();

};

inline void CRecvEvent::SetUserData(TDes8* aData)
{
	iUserData = aData;
}

inline TDes8* CRecvEvent::UserData()
{
	return iUserData;
}

inline CRecvData& CRecvEvent::RecvData()
{
	return (CRecvData&) *iStateMachine;
}

inline void CRecvEvent::SetUserMaxLength(TInt aMaxLength) {
	iUserMaxLength = aMaxLength;
}

//

class CSendData : public CStateMachine
{
public:
	static CSendData* NewL(CTlsConnection& aTlsConnection); 
	~CSendData();
	
	void Start(TRequestStatus* aClientStatus, MStateMachineNotify* aStateMachineNotify);
	
	void Suspend();
	void Resume();
	
	void SetUserData(TDesC8* aData);
	void SetSockXfrLength(TInt* aLen);
		
protected:
	CSendData(CTlsConnection& aTlsConnection);
	void ConstructL(CTlsConnection& aTlsConnection);

	virtual void DoCancel();
	virtual void OnCompletion();

protected:
	CTlsConnection& iTlsConnection;
	CSendEvent& iSendEvent;
	
	TDesC8* iUserData;
	TInt* iSockXfrLength;
	TInt iCurrentPos;
};

inline void CSendData::Start(TRequestStatus* aClientStatus, MStateMachineNotify* aStateMachineNotify)
{
	CStateMachine::Start(aClientStatus, NULL, aStateMachineNotify);
}

inline void CSendData::SetUserData(TDesC8* aData)
{
	iUserData = aData;
}


class CSendEvent : public CAsynchEvent
{
public:
	CSendEvent(CMbedContext& aMbedContext, CBio& aBio);
	~CSendEvent();
	
	virtual CAsynchEvent* ProcessL(TRequestStatus& aStatus);
	
	void SetUserData(TDesC8* aData);
	TDesC8* UserData() const;
	TInt CurrentPos() const;
	void ResetCurrentPos();
	
	void CancelAll();
	void ReConstruct(CStateMachine* aStateMachine, TInt aCurrentPos);

protected:
	CMbedContext& iMbedContext;
	CBio& iBio;
	
	TDesC8* iData;
	TInt* iSockXfrLength;
	TInt iCurrentPos;

};

inline TDesC8* CSendEvent::UserData() const
{
	return iData;
}

inline void CSendEvent::SetUserData(TDesC8* aData)
{
	iData = aData;
}

inline TInt CSendEvent::CurrentPos() const
{
	return iCurrentPos;
}

inline void CSendEvent::ResetCurrentPos()
{
	iCurrentPos = 0;
}

// handshake

class CHandshake : public CStateMachine
{
public:
	static CHandshake* NewL(CTlsConnection& aTlsConnection); 
	~CHandshake();
	
	void Start(TRequestStatus* aClientStatus, MStateMachineNotify* aStateMachineNotify);
	
	void Resume();

protected:
	CHandshake(CTlsConnection& aTlsConnection);
	void ConstructL();

	virtual void DoCancel();
	virtual void OnCompletion();

protected:
	CTlsConnection& iTlsConnection;
	CHandshakeEvent& iHandshakeEvent;
};

inline void CHandshake::Start(TRequestStatus* aClientStatus, MStateMachineNotify* aStateMachineNotify)
{
	CStateMachine::Start(aClientStatus, NULL, aStateMachineNotify);
}



class CHandshakeEvent : public CAsynchEvent
{
public:
	CHandshakeEvent(CMbedContext& aMbedContext, CBio& aBio);
	~CHandshakeEvent();
	
	virtual CAsynchEvent* ProcessL(TRequestStatus& aStatus);
	
	void CancelAll();
	void Set(CStateMachine* aStateMachine);

protected:
	CMbedContext& iMbedContext;
	CBio& iBio;
#ifndef NO_VERIFY
	MSecurityDialog* iSecurityDialog;
#endif
	TBool iInDialog;
	TBool iHandshaked;
};

inline void CHandshakeEvent::Set(CStateMachine* aStateMachine)
{
	iStateMachine = aStateMachine;
}

#endif
