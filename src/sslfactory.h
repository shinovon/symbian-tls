/**
 * Copyright (c) 2026 Arman Jussupgaliyev
 */

#if !defined SSLFACTORY_H && !defined EKA2
#define SSLFACTORY_H
#include <ssl.h>

// bearssl is assumed, since it's eka1 build

class CSSLProviderImpl : public CSSLProviderBase {
public:
	CSSLProviderImpl(CSSLFactory& aFactory) : CSSLProviderBase(aFactory) {}
    ~CSSLProviderImpl();
    
	const TInt GetOption(TUint level, TUint name, TDes8& anOption);
	void Ioctl(TUint level, TUint name, TDes8* anOption);
	void CancelIoctl(TUint aLevel, TUint aName);
	
	TInt SetOption(TUint level, TUint name, const TDesC8 &anOption);
	
	TUint Write(const TDesC8& aDesc, TUint options, TSockAddr* anAddr=NULL);
	
	void Process(RMBufChain& aBuf);
	
	void ProcessL(const TDesC8 &aDesc);
	
	TInt ActiveOpen();
	
	TInt ActiveOpen(const TDesC8& aConnectionData);
	
	TInt PassiveOpen(TUint aQueSize);
	
	TInt PassiveOpen(TUint aQueSize, const TDesC8& aConnectionData);
	
	void Shutdown();
	
	void Close();
	void ConstructL(MSSLSocketNotify *aParent);
	void ConnectCompleted();
};

#endif
