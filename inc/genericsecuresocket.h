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
// Generic Secure Socket Interface
// 
//

/**
 @file
 @internalTechnology
*/

#ifndef __GENERICSECURESOCKET_H__
#define __GENERICSECURESOCKET_H__

#include <e32base.h>
#include <es_sock.h>

class MGenericSecureSocket
/** 
 * Interface to provide Generic Secure Socket Functionality. 
 * 
 * @prototype
 * @internalComponent
 * 
 * @since v9.2 
 */
	{
public:
	/**
	Send data over the generic socket for the secure socket
	@param aDataToSend encrypted data to send for secure socket
	@param aFlags Flags which are passed through to protocol
	@param aStatus Request Status
	*/
	virtual void Send(const TDesC8& aDataToSend, TUint aFlags, TRequestStatus& aStatus)=0;

	/**
	Cancel the current send operation
	*/
	virtual void CancelSend()=0;
	
	/**
	Receive data from the generic socket for the secure socket
	@param aDataReceived encrypted data received for the secure socket
	@param aFlags Flags which are passed through to protocol
	@param aStatus Request Status.  On return KErrNone if successful, 
	       otherwise another of the system-wide error
	*/
	virtual void Recv(TDes8& aDataReceived, TUint aFlags, TRequestStatus& aStatus)=0;

	/**
	Cancel the current recv operation
	*/
	virtual void CancelRecv()=0;
	
	/**
	Read data from the generic socket for the secure socket
	@param aDataRead encrypted data read for the secure socket
	@param aStatus Request Status.  On return KErrNone if successful, 
	       otherwise another of the system-wide error
	*/
	virtual void Read(TDes8& aDataRead, TRequestStatus& aStatus)=0;

	/**
	Cancel the current read operation
	*/
	virtual void CancelRead()=0;

	/**
	Sets a socket option
	@param aOptionName An integer constant which identifies an option.
	@param aOptionLevel An integer constant which identifies level of an option
	@param aOption Option value packaged in a descriptor.
	@return KErrNone if successful, otherwise another of the system-wide error codes. 
	*/
	virtual TInt SetOpt(TUint aOptionName, TUint aOptionLevel, const TDesC8& aOption)=0;

	/**
	Gets a socket option
	@param aOptionName An integer constant which identifies an option.
	@param aOptionLevel An integer constant which identifies level of an option
	@param aOption Option value packaged in a descriptor.
	@return KErrNone if successful, otherwise another of the system-wide error codes. 
	*/
	virtual TInt GetOpt(TUint aOptionName, TUint aOptionLevel, TDes8& aOption)=0;

	/**
	Gets the local address of a bound socket. 
	@param aAddr Local address which is filled in on return. 
	*/
	virtual void LocalName(TSockAddr& aAddr)=0;

	/**
	Gets the remote address of a bound socket. 
	@param aAddr Remote address which is filled in on return. 
	*/
	virtual void RemoteName(TSockAddr& aAddr)=0;

	/**
	Close the Generic Socket
	*/
	virtual void Close()=0;
	};


template<class TYPE>
class CGenericSecureSocket : public MGenericSecureSocket
/** 
 * Templated Class to provide wrapper using Generic Secure Socket
 * 
 * @prototype
 * @internalComponent
 * 
 * @since v9.2 
 */
	{
public:
	CGenericSecureSocket(TYPE& aProvider);
	~CGenericSecureSocket();

	void Send(const TDesC8& aDataToSend, TUint aFlags, TRequestStatus& aStatus);
	void CancelSend();
	
	void Recv(TDes8& aDataReceived, TUint aFlags, TRequestStatus& aStatus);
	void CancelRecv();
	
	void Read(TDes8& aDataRead, TRequestStatus& aStatus);
	void CancelRead();

	TInt SetOpt(TUint aOptionName, TUint aOptionLevel, const TDesC8& aOption);
	TInt GetOpt(TUint aOptionName, TUint aOptionLevel, TDes8& aOption);

	void LocalName(TSockAddr& aAddr);
	void RemoteName(TSockAddr& aAddr);

	void Close();

private:
	TYPE& iProvider;
	};

#include <genericsecuresocket.inl>

#endif // __GENERICSECURESOCKET_H__
