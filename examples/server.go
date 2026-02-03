package main

import (
	"context"
	"errors"
	"fmt"
	"log"

	"go.linka.cloud/ldap"
)

// ///////////
// Sample searches you can try against this simple LDAP server:
//
// ldapsearch -H ldap://localhost:3389 -x -b 'dn=test,dn=com'
// ldapsearch -H ldap://localhost:3389 -x -b 'dn=test,dn=com' 'cn=ned'
// ldapsearch -H ldap://localhost:3389 -x -b 'dn=test,dn=com' 'uidnumber=5000'
// ///////////

// /////////// Run a simple LDAP server
func main() {
	s := ldap.NewServer()
	s.EnforceLDAP = true

	// register Bind and Search function handlers
	handler := ldapHandler{}
	s.BindFunc("", handler)
	s.SearchFunc("", handler)

	// start the server
	listen := "localhost:3389"
	log.Printf("Starting example LDAP server on %s", listen)
	if err := s.ListenAndServe(listen); err != nil {
		log.Fatalf("LDAP Server Failed: %s", err.Error())
	}
}

type ldapHandler struct{}

func (h ldapHandler) Bind(ctx context.Context, bindDN, bindSimplePw string) (ldap.LDAPResultCode, context.Context, error) {
	if bindSimplePw == "password" {
		return ldap.LDAPResultSuccess, context.WithValue(ctx, "user", bindDN), nil
	}
	return ldap.LDAPResultSuccess, ctx, nil
}

// /////////// Return some hardcoded search results - we'll respond to any baseDN for testing
func (h ldapHandler) Search(ctx context.Context, searchReq ldap.SearchRequest) (ldap.ServerSearchResult, error) {
	user, ok := ctx.Value("user").(string)
	if !ok {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, errors.New("Operation unavailable without authentication")
	}
	fmt.Printf("Request from %q (%v): BaseDN=%s Filter=%s\n", user, ldap.Conn(ctx).RemoteAddr(), searchReq.BaseDN, searchReq.Filter)
	entries := []*ldap.Entry{
		{DN: "cn=ned," + searchReq.BaseDN, Attributes: []*ldap.EntryAttribute{
			{Name: "cn", Values: []string{"ned"}},
			{Name: "uidNumber", Values: []string{"5000"}},
			{Name: "accountStatus", Values: []string{"active"}},
			{Name: "uid", Values: []string{"ned"}},
			{Name: "description", Values: []string{"ned"}},
			{Name: "objectClass", Values: []string{"posixAccount"}},
		}},
		{DN: "cn=trent," + searchReq.BaseDN, Attributes: []*ldap.EntryAttribute{
			{Name: "cn", Values: []string{"trent"}},
			{Name: "uidNumber", Values: []string{"5005"}},
			{Name: "accountStatus", Values: []string{"active"}},
			{Name: "uid", Values: []string{"trent"}},
			{Name: "description", Values: []string{"trent"}},
			{Name: "objectClass", Values: []string{"posixAccount"}},
		}},
	}
	return ldap.ServerSearchResult{entries, []string{}, []ldap.Control{}, ldap.LDAPResultSuccess}, nil
}
