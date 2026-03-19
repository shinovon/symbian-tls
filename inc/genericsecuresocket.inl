// Copyright (c) 2005-2009 Nokia Corporation and/or its subsidiary(-ies).
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
// Generic Secure Socket Interface Inline Functions
// 
//

/**
 @file
 @internalTechnology
*/

#ifndef __GENERICSECURESOCKET_INL__
#define __GENERICSECURESOCKET_INL__

template<class TYPE>
inline CGenericSecureSocket<TYPE>::CGenericSecureSocket(TYPE& aProvider)
:    iProvider(aProvider)
/**
Constructor
*/
    {
    }

template<class TYPE>
inline CGenericSecureSocket<TYPE>::~CGenericSecureSocket()
/**
Destructor
*/
    {
    }

template<class TYPE>
inline void CGenericSecureSocket<TYPE>::Send(const TDesC8& aDesc,TUint aFlags, TRequestStatus& aStatus)
/**
Send data over the generic socket for the secure socket
@param aDataToSend encrypted data to send for secure socket
@param aFlags Flags which are passed through to protocol
@param aStatus Request Status
*/
	{
	iProvider.Send(aDesc, aFlags, aStatus);
	}

template<class TYPE>
inline void CGenericSecureSocket<TYPE>::CancelSend()
/**
Cancel the current send operation
*/
	{
	iProvider.CancelSend();
	}

template<class TYPE>
inline void CGenericSecureSocket<TYPE>::Recv(TDes8& aDesc,TUint aFlags, TRequestStatus& aStatus)
/**
Receive data from the generic socket for the secure socket
@param aDataReceived encrypted data received for the secure socket
@param aFlags Flags which are passed through to protocol
@param aStatus Request Status.  On return KErrNone if successful, 
       otherwise another of the system-wide error
*/
	{
	iProvider.Recv(aDesc, aFlags, aStatus);
	}

template<class TYPE>
inline void CGenericSecureSocket<TYPE>::CancelRecv()
/**
Cancel the current recv operation
*/
	{
	iProvider.CancelRecv();
	}


template<class TYPE>
inline void CGenericSecureSocket<TYPE>::Read(TDes8& aDesc, TRequestStatus& aStatus)
/**
Read data from the generic socket for the secure socket
@param aDataRead encrypted data read for the secure socket
@param aStatus Request Status.  On return KErrNone if successful, 
       otherwise another of the system-wide error
*/
	{
	iProvider.Read(aDesc, aStatus);
	}

template<class TYPE>
inline void CGenericSecureSocket<TYPE>::CancelRead()
/**
Cancel the current read operation
*/
	{
	iProvider.CancelRead();
	}

template<class TYPE>
inline TInt CGenericSecureSocket<TYPE>::SetOpt(TUint aOptionName,TUint aOptionLevel,const TDesC8& aOption)
/**
Sets a socket option
@param aOptionName An integer constant which identifies an option.
@param aOptionLevel An integer constant which identifies level of an option
@param aOption Option value packaged in a descriptor.
@return KErrNone if successful, otherwise another of the system-wide error codes. 
*/
	{
	return iProvider.SetOpt(aOptionName, aOptionLevel, aOption);
	}

template<class TYPE>
inline TInt CGenericSecureSocket<TYPE>::GetOpt(TUint aOptionName,TUint aOptionLevel,TDes8& aOption)
/**
Gets a socket option
@param aOptionName An integer constant which identifies an option.
@param aOptionLevel An integer constant which identifies level of an option
@param aOption Option value packaged in a descriptor.
@return KErrNone if successful, otherwise another of the system-wide error codes. 
*/
	{
	return iProvider.GetOpt(aOptionName, aOptionLevel, aOption);
	}

template<class TYPE>
inline void CGenericSecureSocket<TYPE>::RemoteName(TSockAddr& aAddr)
/**
Gets the local address of a bound socket. 
@param aAddr Local address which is filled in on return. 
*/
	{
	iProvider.RemoteName(aAddr);
	}

template<class TYPE>
inline void CGenericSecureSocket<TYPE>::LocalName(TSockAddr& aAddr)
/**
Gets the remote address of a bound socket. 
@param aAddr Remote address which is filled in on return. 
*/
	{
	iProvider.LocalName(aAddr);
	}

template<class TYPE>
inline void CGenericSecureSocket<TYPE>::Close()
/**
Close the Generic Socket
*/
	{
	iProvider.Close();
	}

#endif // __GENERICSECURESOCKET_INL__
