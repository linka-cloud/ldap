package ldap

import (
	"context"
	"crypto/tls"
	"time"
)

// Client knows how to interact with an LDAP server
type Client interface {
	Start(ctx context.Context)
	StartTLS(context.Context,*tls.Config) error
	Close()
	IsClosing() bool
	SetTimeout(time.Duration)

	Bind(ctx context.Context, username, password string) error
	UnauthenticatedBind(ctx context.Context, username string) error
	SimpleBind(context.Context, *SimpleBindRequest) (*SimpleBindResult, error)
	ExternalBind(ctx context.Context) error

	Add(context.Context, *AddRequest) error
	Del(context.Context, *DelRequest) error
	Modify(context.Context, *ModifyRequest) error
	ModifyDN(context.Context, *ModifyDNRequest) error
	ModifyWithResult(context.Context, *ModifyRequest) (*ModifyResult, error)

	Compare(ctx context.Context, dn, attribute, value string) (bool, error)
	PasswordModify(context.Context, *PasswordModifyRequest) (*PasswordModifyResult, error)

	Search(context.Context, *SearchRequest) (*SearchResult, error)
	SearchWithPaging(ctx context.Context, searchRequest *SearchRequest, pagingSize uint32) (*SearchResult, error)
}
