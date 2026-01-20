// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// File contains Search functionality
//
// https://tools.ietf.org/html/rfc4511
//
//         SearchRequest ::= [APPLICATION 3] SEQUENCE {
//              baseObject      LDAPDN,
//              scope           ENUMERATED {
//                   baseObject              (0),
//                   singleLevel             (1),
//                   wholeSubtree            (2),
//                   ...  },
//              derefAliases    ENUMERATED {
//                   neverDerefAliases       (0),
//                   derefInSearching        (1),
//                   derefFindingBaseObj     (2),
//                   derefAlways             (3) },
//              sizeLimit       INTEGER (0 ..  maxInt),
//              timeLimit       INTEGER (0 ..  maxInt),
//              typesOnly       BOOLEAN,
//              filter          Filter,
//              attributes      AttributeSelection }
//
//         AttributeSelection ::= SEQUENCE OF selector LDAPString
//                         -- The LDAPString is constrained to
//                         -- <attributeSelector> in Section 4.5.1.8
//
//         Filter ::= CHOICE {
//              and             [0] SET SIZE (1..MAX) OF filter Filter,
//              or              [1] SET SIZE (1..MAX) OF filter Filter,
//              not             [2] Filter,
//              equalityMatch   [3] AttributeValueAssertion,
//              substrings      [4] SubstringFilter,
//              greaterOrEqual  [5] AttributeValueAssertion,
//              lessOrEqual     [6] AttributeValueAssertion,
//              present         [7] AttributeDescription,
//              approxMatch     [8] AttributeValueAssertion,
//              extensibleMatch [9] MatchingRuleAssertion,
//              ...  }
//
//         SubstringFilter ::= SEQUENCE {
//              type           AttributeDescription,
//              substrings     SEQUENCE SIZE (1..MAX) OF substring CHOICE {
//                   initial [0] AssertionValue,  -- can occur at most once
//                   any     [1] AssertionValue,
//                   final   [2] AssertionValue } -- can occur at most once
//              }
//
//         MatchingRuleAssertion ::= SEQUENCE {
//              matchingRule    [1] MatchingRuleId OPTIONAL,
//              type            [2] AttributeDescription OPTIONAL,
//              matchValue      [3] AssertionValue,
//              dnAttributes    [4] BOOLEAN DEFAULT FALSE }
//
//

package ldap

import (
	"fmt"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
)

const (
	ScopeBaseObject   = 0
	ScopeSingleLevel  = 1
	ScopeWholeSubtree = 2
)

var ScopeMap = map[int]string{
	ScopeBaseObject:   "Base Object",
	ScopeSingleLevel:  "Single Level",
	ScopeWholeSubtree: "Whole Subtree",
}

const (
	NeverDerefAliases   = 0
	DerefInSearching    = 1
	DerefFindingBaseObj = 2
	DerefAlways         = 3
)

var DerefMap = map[int]string{
	NeverDerefAliases:   "NeverDerefAliases",
	DerefInSearching:    "DerefInSearching",
	DerefFindingBaseObj: "DerefFindingBaseObj",
	DerefAlways:         "DerefAlways",
}

type Entry struct {
	DN         string
	Attributes []*EntryAttribute
}

func (e *Entry) GetAttributeValues(attribute string) []string {
	for _, attr := range e.Attributes {
		if attr.Name == attribute {
			return attr.Values
		}
	}
	return []string{}
}

func (e *Entry) GetAttributeValue(attribute string) string {
	values := e.GetAttributeValues(attribute)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func (e *Entry) Print() {
	fmt.Printf("DN: %s\n", e.DN)
	for _, attr := range e.Attributes {
		attr.Print()
	}
}

func (e *Entry) PrettyPrint(indent int) {
	fmt.Printf("%sDN: %s\n", strings.Repeat(" ", indent), e.DN)
	for _, attr := range e.Attributes {
		attr.PrettyPrint(indent + 2)
	}
}

type EntryAttribute struct {
	Name   string
	Values []string
}

func (e *EntryAttribute) Print() {
	fmt.Printf("%s: %s\n", e.Name, e.Values)
}

func (e *EntryAttribute) PrettyPrint(indent int) {
	fmt.Printf("%s%s: %s\n", strings.Repeat(" ", indent), e.Name, e.Values)
}

type SearchResult struct {
	Entries   []*Entry
	Referrals []string
	Controls  []Control
}

func (s *SearchResult) Print() {
	for _, entry := range s.Entries {
		entry.Print()
	}
}

func (s *SearchResult) PrettyPrint(indent int) {
	for _, entry := range s.Entries {
		entry.PrettyPrint(indent)
	}
}

type SearchRequest struct {
	BaseDN       string
	Scope        int
	DerefAliases int
	SizeLimit    int
	TimeLimit    int
	TypesOnly    bool
	Filter       string
	Attributes   []string
	Controls     []Control
}

func (s *SearchRequest) encode() (*ber.Packet, error) {
	request := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationSearchRequest, nil, "Search Request")
	request.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, s.BaseDN, "Base DN"))
	request.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, uint64(s.Scope), "Scope"))
	request.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, uint64(s.DerefAliases), "Deref Aliases"))
	request.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, uint64(s.SizeLimit), "Size Limit"))
	request.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, uint64(s.TimeLimit), "Time Limit"))
	request.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, s.TypesOnly, "Types Only"))
	// compile and encode filter
	filterPacket, err := CompileFilter(s.Filter)
	if err != nil {
		return nil, err
	}
	request.AppendChild(filterPacket)
	// encode attributes
	attributesPacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	for _, attribute := range s.Attributes {
		attributesPacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, attribute, "Attribute"))
	}
	request.AppendChild(attributesPacket)
	return request, nil
}
