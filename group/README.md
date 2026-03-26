# changes between releases

## ER5
- added ssl.dll, which is loaded dynamically in tcpip.prt (to be confirmed). ssl is enabled by calling `SetOpt` with `KSoSecureSocket` in `RSocket`

**not supported**

## 6.0
- ssl.h changes `void ConstructL(MSSLSocketNotify*, CCryptoFactory*, CCertFactory*)`
to `void ConstructL(MSSLSocketNotify*)`
in `CSSLProviderBase`

**not supported**

## 6.1
- ssl.h adds `void SSLDisconnectIndication(TInt)`
before `void SSLIoctlComplete(TDesC8*)`
in `MSSLSocketNotify`

**not supported** (yet?)

## 7.0 <small>(and 6.2)</small>
- ssl.h renames `void Process(const TDesC8&)`
to `void ProcessL(const TDesC8&)`
in `CSSLProviderBase`
- ssladaptor.dll added with 2 exports: `CSslAdaptor::NewL(RSocket&, TDesC16 const&)`, `UnloadDll`, which is loaded dynamically in securesocket.dll (currently only supporting this)

## 8.0
??

## 8.1
- ssl.dll removed, ssladaptor.dll is now new ssl.dll
- removed 2nd export: `UnloadDll`

## 9.1
- 2nd ssl.dll export added: `UnloadDll`

(mbedtls is used from there)

##  9.2
no breaking changes

- `MGenericSecureSocket` is introduced
- 3rd ssl.dll export added: `CTlsConnection::NewL(MGenericSecureSocket&, const TDesC&)`
