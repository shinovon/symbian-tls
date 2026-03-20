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
	IMPORT_C MSecureSocket* NewL(RSocket& aSocket, const TDesC& aProtocol);
	IMPORT_C void UnloadDll(TAny* aPtr);
};

EXPORT_C MSecureSocket* CSslAdaptor::NewL(RSocket& aSocket, const TDesC& aProtocol) {
	return CTlsConnection::NewL(aSocket, aProtocol);
}

EXPORT_C void CSslAdaptor::UnloadDll(TAny* aPtr) {
	return CTlsConnection::UnloadDll(aPtr);
}
