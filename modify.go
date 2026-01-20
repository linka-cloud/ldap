package ldap

import (
	"github.com/go-ldap/ldap/v3"
)

const (
	AddAttribute     = ldap.AddAttribute
	DeleteAttribute  = ldap.DeleteAttribute
	ReplaceAttribute = ldap.ReplaceAttribute
)

type (
	PartialAttribute = ldap.PartialAttribute
	ModifyRequest    = ldap.ModifyRequest
)

func ModifiedAttributes(req ModifyRequest) (add []PartialAttribute, replace []PartialAttribute, del []PartialAttribute) {
	for _, change := range req.Changes {
		switch change.Operation {
		case AddAttribute:
			add = append(add, change.Modification)
		case DeleteAttribute:
			del = append(del, change.Modification)
		case ReplaceAttribute:
			replace = append(replace, change.Modification)
		}
	}
	return add, replace, del
}
