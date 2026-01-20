# LDAP Server for Golang

This library provides basic LDAP v3 functionality for the GO programming language.

The **server** implements Bind and Search from [RFC4510](http://tools.ietf.org/html/rfc4510), has good testing coverage, and is compatible with any LDAPv3 client.  It provides the building blocks for a custom LDAP server, but you must implement the backend datastore of your choice.

## LDAP server notes:
The server library is modeled after net/http - you designate handlers for the LDAP operations you want to support (Bind/Search/etc.), then start the server with ListenAndServe().  You can specify different handlers for different baseDNs - they must implement the interfaces of the operations you want to support:
```go
type Binder interface {
    Bind(bindDN, bindSimplePw string, conn net.Conn) (LDAPResultCode, error)
}
type Searcher interface {
    Search(boundDN string, searchReq SearchRequest, conn net.Conn) (ServerSearchResult, error)
}
type Closer interface {
    Close(conn net.Conn) error
}
```

### A basic bind-only LDAP server
```go
func main() {
  s := ldap.NewServer()
  handler := ldapHandler{}
  s.BindFunc("", handler)
  if err := s.ListenAndServe("localhost:389"); err != nil {
    log.Fatal("LDAP Server Failed: %s", err.Error())
  }
}
type ldapHandler struct {
}
func (h ldapHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (ldap.LDAPResultCode, error) {
	if bindDN == "" && bindSimplePw == "" {
		return ldap.LDAPResultSuccess, nil
	}
	return ldap.LDAPResultInvalidCredentials, nil
}
```

* Server.EnforceLDAP: Normally, the LDAP server will return whatever results your handler provides.  Set the **Server.EnforceLDAP** flag to **true** and the server will apply the LDAP **search filter**, **attributes limits**, **size/time limits**, **search scope**, and **base DN matching** to your handler's dataset.  This makes it a lot simpler to write a custom LDAP server without worrying about LDAP internals.

### LDAP server examples:
* examples/server.go: **Basic LDAP authentication (bind and search only)**
* examples/proxy.go: **Simple LDAP proxy server.**
* server_test.go: **The _test.go files have examples of all server functions.**

### Known limitations:

* Golang's TLS implementation does not support SSLv2.  Some old OSs require SSLv2, and are not able to connect to an LDAP server created with this library's ListenAndServeTLS() function.  If you *must* support legacy (read: *insecure*) SSLv2 clients, run your LDAP server behind HAProxy.

### Not implemented:
From the server perspective, all of [RFC4510](http://tools.ietf.org/html/rfc4510) is implemented **except**:
* 4.5.1.3.  SearchRequest.derefAliases
* 4.5.1.5.  SearchRequest.timeLimit
* 4.5.1.6.  SearchRequest.typesOnly

*Server library by: [nmcclain](https://github.com/nmcclain)*
