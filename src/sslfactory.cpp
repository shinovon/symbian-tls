/**
 * Copyright (c) 2026 Arman Jussupgaliyev
 */

#ifndef EKA2
#include "sslfactory.h"
#include "logfile.h"

EXPORT_C CSSLFactory* NewCSSLFactoryL() {
	LOG(Log::Init());
	LOG(Log::Printf(_L("NewCSSLFactoryL()")));
	CSSLFactory* self = new (ELeave) CSSLFactory();
	CleanupStack::PushL(self);
	self->ConstructL();
	CleanupStack::Pop();
	return self;
}

CSSLFactory::CSSLFactory() :
	iSecureSocketsCount(0)
{
	LOG(Log::Printf(_L("CSSLFactory::CSSLFactory()")));
}

CSSLFactory::~CSSLFactory() {
	LOG(Log::Printf(_L("CSSLFactory::~CSSLFactory()")));
}

void CSSLFactory::ConstructL() {
	LOG(Log::Printf(_L("CSSLFactory::ConstructL()")));
	iSecureSocketsList.SetOffset(_FOFF(CSSLProviderBase, iLink));

	InitCryptoL();
}

void CSSLFactory::InitCryptoL(){
	LOG(Log::Printf(_L("CSSLFactory::InitCryptoL()")));
}

TVersion CSSLFactory::Version() const {
	LOG(Log::Printf(_L("CSSLFactory::Version()")));
	return TVersion(KSSLMajorVersionNumber, KSSLMinorVersionNumber, KSSLBuildVersionNumber);
}

TInt CSSLFactory::Open() {
	LOG(Log::Printf(_L("CSSLFactory::Open()")));
	return CObject::Open();
}

void CSSLFactory::Close() {
	LOG(Log::Printf(_L("CSSLFactory::Close()")));
	CObject::Close();
}

void CSSLFactory::SetSessionStateL(CSSLSessionState* /*aState*/, const TDesC8& /*aID*/) {
	LOG(Log::Printf(_L("CSSLFactory::SetSessionStateL()")));
}

TPtrC8 CSSLFactory::GetSession(const TDesC8& /*aID*/, CSSLSessionState* /*aState*/) {
	LOG(Log::Printf(_L("CSSLFactory::GetSession()")));
	return TPtrC8();
}

void CSSLFactory::InitL(RLibrary& aLib, CObjectCon& /*aCon*/) {
	LOG(Log::Printf(_L("CSSLFactory::InitL()")));
	iLib = aLib;
}

void CSSLFactory::SecureSocketShutdown(CSSLProviderBase *aSecureSocket) {
	LOG(Log::Printf(_L("CSSLFactory::SecureSocketShutdown()")));
	if (aSecureSocket) {
		aSecureSocket->iLink.Deque();
		iSecureSocketsCount--;
	}
}

CSSLProviderBase* CSSLFactory::NewSecureSocketL(MSSLSocketNotify* aParent) {
	LOG(Log::Printf(_L("CSSLFactory::CSSLFactory::NewSecureSocketL()")));
	CSSLProviderImpl* socket = new (ELeave) CSSLProviderImpl(*this);
	CleanupStack::PushL(socket);

	socket->ConstructL(aParent);

	CleanupStack::Pop(socket);

	iSecureSocketsList.AddLast(*socket);
	iSecureSocketsCount++;

	return socket;
}

// CSSLProviderImpl

TInt CSSLProviderImpl::PassiveOpen(TUint /*aQueSize*/) {
	LOG(Log::Printf(_L("CSSLProviderImpl::PassiveOpen()")));
	return KErrNotSupported;
}

TInt CSSLProviderImpl::PassiveOpen(TUint /*aQueSize*/, const TDesC8& /*aConnectionData*/) {
	LOG(Log::Printf(_L("CSSLProviderImpl::PassiveOpen()")));
	return KErrNotSupported;
}

void CSSLProviderImpl::Ioctl(TUint /*level*/, TUint /*name*/, TDes8* /*anOption*/) {
	LOG(Log::Printf(_L("CSSLProviderImpl::Ioctl()")));
}

void CSSLProviderImpl::CancelIoctl(TUint /*aLevel*/, TUint /*aName*/) {
	LOG(Log::Printf(_L("CSSLProviderImpl::CancelIoctl()")));
}

const TInt CSSLProviderImpl::GetOption(TUint /*level*/, TUint /*name*/, TDes8& /*anOption*/) {
	LOG(Log::Printf(_L("CSSLProviderImpl::GetOption()")));
	return KErrNotSupported;
}

TInt CSSLProviderImpl::SetOption(TUint /*level*/, TUint /*name*/, const TDesC8& /*anOption*/) {
	LOG(Log::Printf(_L("CSSLProviderImpl::SetOption()")));
	// TODO
	return KErrNone;
}

void CSSLProviderImpl::ConstructL(MSSLSocketNotify* aParent) {
	LOG(Log::Printf(_L("CSSLProviderImpl::ConstructL()")));
	SetNotify(aParent);
}

TInt CSSLProviderImpl::ActiveOpen() {
	LOG(Log::Printf(_L("CSSLProviderImpl::ActiveOpen()")));
	return KErrNone;
}

TInt CSSLProviderImpl::ActiveOpen(const TDesC8& /*aConnectionData*/) {
	LOG(Log::Printf(_L("CSSLProviderImpl::ActiveOpen()")));
	return ActiveOpen();
}

void CSSLProviderImpl::Process(RMBufChain& aBuf) {
	LOG(Log::Printf(_L("CSSLProviderImpl::Process()")));
	// TODO
}

void CSSLProviderImpl::ProcessL(const TDesC8& aDesc) {
	LOG(Log::Printf(_L("CSSLProviderImpl::ProcessL()")));
	// TODO
}

TUint CSSLProviderImpl::Write(const TDesC8& aDesc, TUint /*options*/, TSockAddr* /*anAddr*/) {
	LOG(Log::Printf(_L("CSSLProviderImpl::Write()")));
	// TODO
	return aDesc.Length();
}

CSSLProviderImpl::~CSSLProviderImpl() {
	LOG(Log::Printf(_L("CSSLProviderImpl::~CSSLProviderImpl()")));
}

void CSSLProviderImpl::ConnectCompleted() {
	LOG(Log::Printf(_L("CSSLProviderImpl::ConnectCompleted()")));
}

void CSSLProviderImpl::Shutdown() {
	LOG(Log::Printf(_L("CSSLProviderImpl::Shutdown()")));
}

void CSSLProviderImpl::Close() {
	LOG(Log::Printf(_L("CSSLProviderImpl::Close()")));
}

// CSSLProviderBase stub

CSSLProviderBase::CSSLProviderBase(CSSLFactory& aFactory) :
	iFactory(&aFactory) {
}

CSSLProviderBase::~CSSLProviderBase() {
}

void CSSLProviderBase::SetNotify(MSSLSocketNotify* aNotify) {
	iSocket = aNotify;
}

#endif
