package ldap

import (
	"github.com/go-ldap/ldap/v3"
)

const (
	ScopeBaseObject   = ldap.ScopeBaseObject
	ScopeSingleLevel  = ldap.ScopeSingleLevel
	ScopeWholeSubtree = ldap.ScopeWholeSubtree
)

const (
	NeverDerefAliases   = ldap.NeverDerefAliases
	DerefInSearching    = ldap.DerefInSearching
	DerefFindingBaseObj = ldap.DerefFindingBaseObj
	DerefAlways         = ldap.DerefAlways
)

type (
	Entry          = ldap.Entry
	EntryAttribute = ldap.EntryAttribute
	SearchResult   = ldap.SearchResult
	SearchRequest  = ldap.SearchRequest
)
