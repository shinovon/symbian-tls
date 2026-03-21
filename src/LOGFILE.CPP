// Copyright (c) 1997-2009 Nokia Corporation and/or its subsidiary(-ies).
// All rights reserved.
// This component and the accompanying materials are made available
// under the terms of "Eclipse Public License v2.0"
// which accompanies this distribution, and is available
// at the URL "http://www.eclipse.org/legal/epl-v20.html".
//
// Initial Contributors:
// Nokia Corporation - initial contribution.
//
// Contributors:
//
// Description:
//

#include <e32std.h>
#include <e32base.h>
#ifdef EKA2
#include <e32debug.h>
#else
#include <e32svr.h>
#endif
#include "LOGFILE.H"

#if defined(__TRACEFILE__)

const TInt KHexDumpWidth = 16;

#if !defined __WINSCW__ && !defined EKA2 && 0
#define DYNAMIC

// can't have wsd in eka1, need to use dll tls..
static void(*Logger_Write16)(const TDesC& , const TDesC& , TFileLoggingMode , const TDesC16& );
static void(*Logger_Write8)(const TDesC& , const TDesC& , TFileLoggingMode , const TDesC8& );
#endif



void Log::Init()
{
#ifdef DYNAMIC
	RLibrary lib;
	if (lib.Load(_L("comsdbgutil.dll")) == KErrNone) {
		Logger_Write16 = (void(*)(const TDesC& , const TDesC& , TFileLoggingMode , const TDesC16& ))lib.Lookup(12);
		Logger_Write8 = (void(*)(const TDesC& , const TDesC& , TFileLoggingMode , const TDesC8& ))lib.Lookup(24);
	} else {
		Logger_Write16 = NULL;
		Logger_Write8 = NULL;
	}
	lib.Close();
#endif
}

void Log::Write(const TDesC& aDes)
	{
#ifdef DYNAMIC
	if (Logger_Write16 != NULL) {
		Logger_Write16(KSSLLogDir,KSSLLogFileName,EFileLoggingModeAppend,aDes);
	}
#else
	RFileLogger::Write(KSSLLogDir,KSSLLogFileName,EFileLoggingModeAppend,aDes);
#endif
	}

void Log::Write8(const TDesC8& aDes)
	{
#ifdef DYNAMIC
	if (Logger_Write8 != NULL) {
		Logger_Write8(KSSLLogDir,KSSLLogFileName,EFileLoggingModeAppend,aDes);
	}
#else
	RFileLogger::Write(KSSLLogDir,KSSLLogFileName,EFileLoggingModeAppend,aDes);
#endif
	}


void Log::Printf(TRefByValue<const TDesC> aFmt, ...)
	{
    //coverity[var_decl];
    VA_LIST list;
    VA_START(list, aFmt);
	TBuf<0x100> buf;
    //coverity[uninit_use_in_call];
    buf.FormatList(aFmt, list);
	Write(buf);
#ifdef EKA2
	RDebug::RawPrint(buf);
#endif
	}
void Log::Printf8(TRefByValue<const TDesC8> aFmt, ...)
	{
    //coverity[var_decl];
    VA_LIST list;
    VA_START(list, aFmt);
	TBuf8<0x100> buf;
    //coverity[uninit_use_in_call];
    buf.FormatList(aFmt, list);
	Write8(buf);
#ifdef EKA2
	RDebug::RawPrint(buf);
#endif
	}

void Log::HexDump(const TText* aHeader, const TText* aMargin, const TUint8* aPtr, TInt aLen)
	{

	TBuf<0x100> buf;
	buf.SetLength(0);
	TInt i = 0;
	const TText* p = aHeader;
	while (aLen>0)
		{
		TInt n = aLen>KHexDumpWidth ? KHexDumpWidth : aLen;
		buf.AppendFormat(_L("%s%04x : "), p, i);
		TInt j;
		for (j=0; j<n; j++)
			buf.AppendFormat(_L("%02x "), aPtr[i+j]);
		while (j++<KHexDumpWidth)
			buf.AppendFormat(_L("   "));
		buf.AppendFormat(_L(" "));
		for (j=0; j<n; j++)
			buf.AppendFormat(_L("%c"), aPtr[i+j]<32 || aPtr[i+j]>126 ? '.' : aPtr[i+j]);
		buf.AppendFormat(_L("\r\n"));
		Log::Write(buf);
		buf.SetLength(0);
		aLen -= n;
		i += n;
		p = aMargin;
		}
	}


#endif // __TRACEFILE__
