package ldap

import (
	"context"
	"log"
)

// This example shows how to rename an entry without moving it
func ExampleConn_ModifyDN_renameNoMove() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, err := DialURL(ctx, "ldap://ldap.example.org:389")
	if err != nil {
		log.Fatalf("Failed to connect: %s\n", err)
	}
	defer conn.Close()

	_, err = conn.SimpleBind(ctx, &SimpleBindRequest{
		Username: "uid=someone,ou=people,dc=example,dc=org",
		Password: "MySecretPass",
	})
	if err != nil {
		log.Fatalf("Failed to bind: %s\n", err)
	}
	// just rename to uid=new,ou=people,dc=example,dc=org:
	req := NewModifyDNRequest("uid=user,ou=people,dc=example,dc=org", "uid=new", true, "")
	if err = conn.ModifyDN(ctx, req); err != nil {
		log.Fatalf("Failed to call ModifyDN(): %s\n", err)
	}
}

// This example shows how to rename an entry and moving it to a new base
func ExampleConn_ModifyDN_renameAndMove() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, err := DialURL(ctx, "ldap://ldap.example.org:389")
	if err != nil {
		log.Fatalf("Failed to connect: %s\n", err)
	}
	defer conn.Close()

	_, err = conn.SimpleBind(ctx, &SimpleBindRequest{
		Username: "uid=someone,ou=people,dc=example,dc=org",
		Password: "MySecretPass",
	})
	if err != nil {
		log.Fatalf("Failed to bind: %s\n", err)
	}
	// rename to uid=new,ou=people,dc=example,dc=org and move to ou=users,dc=example,dc=org ->
	// uid=new,ou=users,dc=example,dc=org
	req := NewModifyDNRequest("uid=user,ou=people,dc=example,dc=org", "uid=new", true, "ou=users,dc=example,dc=org")

	if err = conn.ModifyDN(ctx, req); err != nil {
		log.Fatalf("Failed to call ModifyDN(): %s\n", err)
	}
}

// This example shows how to move an entry to a new base without renaming the RDN
func ExampleConn_ModifyDN_moveOnly() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, err := DialURL(ctx, "ldap://ldap.example.org:389")
	if err != nil {
		log.Fatalf("Failed to connect: %s\n", err)
	}
	defer conn.Close()

	_, err = conn.SimpleBind(ctx, &SimpleBindRequest{
		Username: "uid=someone,ou=people,dc=example,dc=org",
		Password: "MySecretPass",
	})
	if err != nil {
		log.Fatalf("Failed to bind: %s\n", err)
	}
	// move to ou=users,dc=example,dc=org -> uid=user,ou=users,dc=example,dc=org
	req := NewModifyDNRequest("uid=user,ou=people,dc=example,dc=org", "uid=user", true, "ou=users,dc=example,dc=org")
	if err = conn.ModifyDN(ctx, req); err != nil {
		log.Fatalf("Failed to call ModifyDN(): %s\n", err)
	}
}
