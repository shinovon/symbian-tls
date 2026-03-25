/**
 * Copyright (c) 2026 Arman Jussupgaliyev
 */

#include <e32base.h>
#include <ssl.h>
#define BEARSSL
#define NO_VERIFY
#include "tlsconnection.h"

#ifndef EKA2
TInt E32Dll(TDllReason) {
	return KErrNone;
}
#endif

class CSslAdaptor {
public:
	static IMPORT_C MSecureSocket* NewL(RSocket& aSocket, const TDesC& aProtocol);
};

EXPORT_C MSecureSocket* CSslAdaptor::NewL(RSocket& aSocket, const TDesC& aProtocol) {
	return CTlsConnection::NewL(aSocket, aProtocol);
}

EXPORT_C void UnloadDll(TAny* aPtr) {
	return CTlsConnection::UnloadDll(aPtr);
}
