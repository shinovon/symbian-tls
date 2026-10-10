# Notes

- StateMachine.cpp is included to avoid linking with netsm.dll, as its .lib is excluded from the most of SDKs.
- comsdbgutil.dll is linked on runtime in debug build, due to similar reason.
- EKA1 version (ssl_bearssl.mmp, ssladaptor.mmp) uses statically linked bearssl.
- ssl_bearssl.mmp can be used on EKA2 if you really want, rename it to ssl.dll after compiling.
- on 8.0a instead of shadowing ssladaptor.dll, securesocket.dll is shadowed with patched runtime linkage to ssladapto2.dll

# SSL API changes between releases

## ER5
- added ssl.dll with 1 export: `NewSSLFactoryL`, which is loaded dynamically in tcpip.prt. ssl is enabled by calling `SetOpt` with `KSoSecureSocket` in `RSocket`

**not supported**

## 6.0 (S80v1)
- ssl.h changes `void ConstructL(MSSLSocketNotify*, CCryptoFactory*, CCertFactory*)`
to `void ConstructL(MSSLSocketNotify*)`
in `CSSLProviderBase`

**not supported**

## 6.1 (S60v0.9)
- ssl.h adds `void SSLDisconnectIndication(TInt)`
before `void SSLIoctlComplete(TDesC8*)`
in `MSSLSocketNotify`

**not supported** (yet?)

## 7.0 (UIQ2), 7.0s (S60v2.0)
(documented as since 6.2)
- ssl.h renames `void Process(const TDesC8&)`
to `void ProcessL(const TDesC8&)`
in `CSSLProviderBase`
- ssladaptor.dll added with 2 exports: `CSslAdaptor::NewL(RSocket&, TDesC16 const&)`, `UnloadDll`, which is loaded dynamically in securesocket.dll (currently only supporting this)
- `KSoSecureSocket` is deprecated, securesocket.dll api replaced it

**not tested on uiq2**

## N-Gage QD, S60v1.2 SDK
- added 7.0 features subset: ssl70.dll, ssladaptor.dll, securesocket.dll, inetprotutil.dll. doesn't seem to be used anywhere.

## 7.0s (S60v2.1, S80v2, S90)
- ssl.h replaces `void SSLDeliver(const TDesC8&, TUint)`
with `void SSLDeliver(const TDesC8&)`
in `MSSLSocketNotify`

## 8.0a (S60v2.6)
- ssl.h replaces `void SSLDeliver(const TDesC8&)`
  with `void SSLDeliver(const TDesC8&, TUint)`
  in `MSSLSocketNotify`

## 8.1a (S60v2.8)
- old ssl.dll removed, ssladaptor.dll is now new ssl.dll
- removed 2nd export

## 9.1
- 2nd ssl.dll export added: `CTlsConnection::UnloadDll(TAny*)`

(mbedtls is used from there)

##  9.2
no breaking changes

- `MGenericSecureSocket` is introduced
- 3rd ssl.dll export added: `CTlsConnection::NewL(MGenericSecureSocket&, const TDesC&)`
