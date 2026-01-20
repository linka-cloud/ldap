package ldap

import (
	"context"
	"net"
	"os/exec"
	"strings"
	"testing"
)

func TestAdd(t *testing.T) {
	s := NewServer()
	s.BindFunc("", modifyTestHandler{})
	s.AddFunc("", modifyTestHandler{})

	LaunchServerForTest(t, s, func() {
		cmd := exec.Command("ldapadd", "-v", "-H", ldapURL, "-x", "-f", "tests/add.ldif")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "modify complete") {
			t.Errorf("ldapadd failed: %v", string(out))
		}
		cmd = exec.Command("ldapadd", "-v", "-H", ldapURL, "-x", "-f", "tests/add2.ldif")
		out, _ = cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_add: Insufficient access") {
			t.Errorf("ldapadd should have failed: %v", string(out))
		}
		if strings.Contains(string(out), "modify complete") {
			t.Errorf("ldapadd should have failed: %v", string(out))
		}
	})
}

func TestDelete(t *testing.T) {
	s := NewServer()
	s.BindFunc("", modifyTestHandler{})
	s.DeleteFunc("", modifyTestHandler{})

	LaunchServerForTest(t, s, func() {
		cmd := exec.Command("ldapdelete", "-v", "-H", ldapURL, "-x", "cn=Delete Me,dc=example,dc=com")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "Delete Result: Success (0)") || !strings.Contains(string(out), "Additional info: Success") {
			t.Errorf("ldapdelete failed: %v", string(out))
		}
		cmd = exec.Command("ldapdelete", "-v", "-H", ldapURL, "-x", "cn=Bob,dc=example,dc=com")
		out, _ = cmd.CombinedOutput()
		if strings.Contains(string(out), "Success") || !strings.Contains(string(out), "ldap_delete: Insufficient access") {
			t.Errorf("ldapdelete should have failed: %v", string(out))
		}
	})
}

func TestModify(t *testing.T) {
	s := NewServer()
	s.BindFunc("", modifyTestHandler{})
	s.ModifyFunc("", modifyTestHandler{})
	LaunchServerForTest(t, s, func() {
		cmd := exec.Command("ldapmodify", "-v", "-H", ldapURL, "-x", "-f", "tests/modify.ldif")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "modify complete") {
			t.Errorf("ldapmodify failed: %v", string(out))
		}
		cmd = exec.Command("ldapmodify", "-v", "-H", ldapURL, "-x", "-f", "tests/modify2.ldif")
		out, _ = cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_modify: Insufficient access") || strings.Contains(string(out), "modify complete") {
			t.Errorf("ldapmodify should have failed: %v", string(out))
		}
	})
}

/*
func TestModifyDN(t *testing.T) {
	s := NewServer()
	s.BindFunc("", modifyTestHandler{})
	s.AddFunc("", modifyTestHandler{})

	LaunchServerForTest(t, s, func() {
		cmd := exec.Command("ldapadd", "-v", "-H", ldapURL, "-x", "-f", "tests/add.ldif")
		//ldapmodrdn -H ldap://localhost:3389 -x "uid=babs,dc=example,dc=com" "uid=babsy,dc=example,dc=com"
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "modify complete") {
			t.Errorf("ldapadd failed: %v", string(out))
		}
		cmd = exec.Command("ldapadd", "-v", "-H", ldapURL, "-x", "-f", "tests/add2.ldif")
		out, _ = cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_add: Insufficient access") {
			t.Errorf("ldapadd should have failed: %v", string(out))
		}
		if strings.Contains(string(out), "modify complete") {
			t.Errorf("ldapadd should have failed: %v", string(out))
		}
	})
}
*/

type modifyTestHandler struct{}

func (h modifyTestHandler) Bind(ctx context.Context, bindDN, bindSimplePw string, conn net.Conn) (LDAPResultCode, error) {
	if bindDN == "" && bindSimplePw == "" {
		return LDAPResultSuccess, nil
	}
	return LDAPResultInvalidCredentials, nil
}

func (h modifyTestHandler) Add(ctx context.Context, boundDN string, req AddRequest, conn net.Conn) (LDAPResultCode, error) {
	// only succeed on expected contents of add.ldif:
	if len(req.Attributes) == 5 && req.DN == "cn=Barbara Jensen,dc=example,dc=com" &&
		req.Attributes[2].Type == "sn" && len(req.Attributes[2].Vals) == 1 &&
		req.Attributes[2].Vals[0] == "Jensen" {
		return LDAPResultSuccess, nil
	}
	return LDAPResultInsufficientAccessRights, nil
}

func (h modifyTestHandler) Delete(ctx context.Context, boundDN, deleteDN string, conn net.Conn) (LDAPResultCode, error) {
	// only succeed on expected deleteDN
	if deleteDN == "cn=Delete Me,dc=example,dc=com" {
		return LDAPResultSuccess, nil
	}
	return LDAPResultInsufficientAccessRights, nil
}

func (h modifyTestHandler) Modify(ctx context.Context, boundDN string, req ModifyRequest, conn net.Conn) (LDAPResultCode, error) {
	add, replace, del := ModifiedAttributes(req)
	// only succeed on expected contents of modify.ldif:
	if req.DN == "cn=testy,dc=example,dc=com" && len(add) == 1 &&
		len(del) == 3 && len(replace) == 2 &&
		del[2].Type == "details" && len(del[2].Vals) == 0 {
		return LDAPResultSuccess, nil
	}
	return LDAPResultInsufficientAccessRights, nil
}

func (h modifyTestHandler) ModifyDN(ctx context.Context, boundDN string, req ModifyDNRequest, conn net.Conn) (LDAPResultCode, error) {
	return LDAPResultInsufficientAccessRights, nil
}
