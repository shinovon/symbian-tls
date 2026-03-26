# SSL API changes between releases

## ER5
- added ssl.dll with 1 export: `NewSSLFactoryL`, which is loaded dynamically in tcpip.prt (to be confirmed). ssl is enabled by calling `SetOpt` with `KSoSecureSocket` in `RSocket`

**not supported**

## 6.0 (S80v1)
- ssl.h changes `void ConstructL(MSSLSocketNotify*, CCryptoFactory*, CCertFactory*)`
to `void ConstructL(MSSLSocketNotify*)`
in `CSSLProviderBase`

**not supported**

## 6.1 (S60v1)
- ssl.h adds `void SSLDisconnectIndication(TInt)`
before `void SSLIoctlComplete(TDesC8*)`
in `MSSLSocketNotify`

**not supported** (yet?)

## 7.0 (S60v2.0)
(documented as since 6.2)
- ssl.h renames `void Process(const TDesC8&)`
to `void ProcessL(const TDesC8&)`
in `CSSLProviderBase`
- ssladaptor.dll added with 2 exports: `CSslAdaptor::NewL(RSocket&, TDesC16 const&)`, `UnloadDll`, which is loaded dynamically in securesocket.dll (currently only supporting this)
- `KSoSecureSocket` is deprecated

## 7.0 (S60v2.1, S80v2, S90, UIQ2)
- ssl.h replaces `void SSLDeliver(const TDesC8&, TUint)`
with `void SSLDeliver(const TDesC8&)`
in `MSSLSocketNotify`

**not tested on uiq2**

## 8.0 (S60v2.6)
- ssl.h replaces `void SSLDeliver(const TDesC8&)`
  with `void SSLDeliver(const TDesC8&, TUint)`
  in `MSSLSocketNotify`

**currently does not work on hardware**

## 8.1 (S60v2.8)
- ssl.dll removed, ssladaptor.dll is now new ssl.dll
- removed 2nd export

## 9.1
- 2nd ssl.dll export added: `CTlsConnection::UnloadDll(TAny*)`

(mbedtls is used from there)

##  9.2
no breaking changes

- `MGenericSecureSocket` is introduced
- 3rd ssl.dll export added: `CTlsConnection::NewL(MGenericSecureSocket&, const TDesC&)`
