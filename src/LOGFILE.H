// Copyright (c) 1997-2009 Nokia Corporation and/or its subsidiary(-ies).
// All rights reserved.
// This component and the accompanying materials are made available
// under the terms of "Eclipse Public License v1.0"
// which accompanies this distribution, and is available
// at the URL "http://www.eclipse.org/legal/epl-v10.html".
//
// Initial Contributors:
// Nokia Corporation - initial contribution.
//
// Contributors:
//
// Description:
//

#if !defined(__SSL_LOGFILE_H__)
#define __SSL_LOGFILE_H__

#ifdef _DEBUG
#include <comms-infras/commsdebugutility.h>
#define __TRACEFILE__
#endif

//#ifndef __WINSCW__
//#undef __TRACEFILE__
//#endif

#ifdef __TRACEFILE__
	#define LOG(a) a	
#else
	#define LOG(a)
#endif

#ifdef __TRACEFILE__
_LIT(KSSLLogFileName,"SSLLog.txt");
_LIT(KSSLLogDir,"SSL");

class CSSLProviderBase;
class RFile;
class Log
	{
public:
	 static void Write(const TDesC& aDes);
	 static void Write8(const TDesC8& aDes);
	 static void Printf(TRefByValue<const TDesC> aFmt, ...);
	 static void Printf8(TRefByValue<const TDesC8> aFmt, ...);
	 static void HexDump(const TText* aHeader, const TText* aMargin, const TUint8* aPtr, TInt aLen);
	};

#endif // __TRACEFILE__

#endif // __SSL_LOGFILE_H__
