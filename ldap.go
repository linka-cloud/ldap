// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldap

import (
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// LDAP Application Codes
const (
	ApplicationBindRequest           = 0
	ApplicationBindResponse          = 1
	ApplicationUnbindRequest         = 2
	ApplicationSearchRequest         = 3
	ApplicationSearchResultEntry     = 4
	ApplicationSearchResultDone      = 5
	ApplicationModifyRequest         = 6
	ApplicationModifyResponse        = 7
	ApplicationAddRequest            = 8
	ApplicationAddResponse           = 9
	ApplicationDelRequest            = 10
	ApplicationDelResponse           = 11
	ApplicationModifyDNRequest       = 12
	ApplicationModifyDNResponse      = 13
	ApplicationCompareRequest        = 14
	ApplicationCompareResponse       = 15
	ApplicationAbandonRequest        = 16
	ApplicationSearchResultReference = 19
	ApplicationExtendedRequest       = 23
	ApplicationExtendedResponse      = 24
)

var ApplicationMap = map[ber.Tag]string{
	ApplicationBindRequest:           "Bind Request",
	ApplicationBindResponse:          "Bind Response",
	ApplicationUnbindRequest:         "Unbind Request",
	ApplicationSearchRequest:         "Search Request",
	ApplicationSearchResultEntry:     "Search Result Entry",
	ApplicationSearchResultDone:      "Search Result Done",
	ApplicationModifyRequest:         "Modify Request",
	ApplicationModifyResponse:        "Modify Response",
	ApplicationAddRequest:            "Add Request",
	ApplicationAddResponse:           "Add Response",
	ApplicationDelRequest:            "Del Request",
	ApplicationDelResponse:           "Del Response",
	ApplicationModifyDNRequest:       "Modify DN Request",
	ApplicationModifyDNResponse:      "Modify DN Response",
	ApplicationCompareRequest:        "Compare Request",
	ApplicationCompareResponse:       "Compare Response",
	ApplicationAbandonRequest:        "Abandon Request",
	ApplicationSearchResultReference: "Search Result Reference",
	ApplicationExtendedRequest:       "Extended Request",
	ApplicationExtendedResponse:      "Extended Response",
}

// LDAP Result Codes
const (
	LDAPResultSuccess                      = 0
	LDAPResultOperationsError              = 1
	LDAPResultProtocolError                = 2
	LDAPResultTimeLimitExceeded            = 3
	LDAPResultSizeLimitExceeded            = 4
	LDAPResultCompareFalse                 = 5
	LDAPResultCompareTrue                  = 6
	LDAPResultAuthMethodNotSupported       = 7
	LDAPResultStrongAuthRequired           = 8
	LDAPResultReferral                     = 10
	LDAPResultAdminLimitExceeded           = 11
	LDAPResultUnavailableCriticalExtension = 12
	LDAPResultConfidentialityRequired      = 13
	LDAPResultSaslBindInProgress           = 14
	LDAPResultNoSuchAttribute              = 16
	LDAPResultUndefinedAttributeType       = 17
	LDAPResultInappropriateMatching        = 18
	LDAPResultConstraintViolation          = 19
	LDAPResultAttributeOrValueExists       = 20
	LDAPResultInvalidAttributeSyntax       = 21
	LDAPResultNoSuchObject                 = 32
	LDAPResultAliasProblem                 = 33
	LDAPResultInvalidDNSyntax              = 34
	LDAPResultAliasDereferencingProblem    = 36
	LDAPResultInappropriateAuthentication  = 48
	LDAPResultInvalidCredentials           = 49
	LDAPResultInsufficientAccessRights     = 50
	LDAPResultBusy                         = 51
	LDAPResultUnavailable                  = 52
	LDAPResultUnwillingToPerform           = 53
	LDAPResultLoopDetect                   = 54
	LDAPResultNamingViolation              = 64
	LDAPResultObjectClassViolation         = 65
	LDAPResultNotAllowedOnNonLeaf          = 66
	LDAPResultNotAllowedOnRDN              = 67
	LDAPResultEntryAlreadyExists           = 68
	LDAPResultObjectClassModsProhibited    = 69
	LDAPResultAffectsMultipleDSAs          = 71
	LDAPResultOther                        = 80

	ErrorNetwork         = 200
	ErrorFilterCompile   = 201
	ErrorFilterDecompile = 202
	ErrorDebugging       = 203
)

var LDAPResultCodeMap = map[LDAPResultCode]string{
	LDAPResultSuccess:                      "Success",
	LDAPResultOperationsError:              "Operations Error",
	LDAPResultProtocolError:                "Protocol Error",
	LDAPResultTimeLimitExceeded:            "Time Limit Exceeded",
	LDAPResultSizeLimitExceeded:            "Size Limit Exceeded",
	LDAPResultCompareFalse:                 "Compare False",
	LDAPResultCompareTrue:                  "Compare True",
	LDAPResultAuthMethodNotSupported:       "Auth Method Not Supported",
	LDAPResultStrongAuthRequired:           "Strong Auth Required",
	LDAPResultReferral:                     "Referral",
	LDAPResultAdminLimitExceeded:           "Admin Limit Exceeded",
	LDAPResultUnavailableCriticalExtension: "Unavailable Critical Extension",
	LDAPResultConfidentialityRequired:      "Confidentiality Required",
	LDAPResultSaslBindInProgress:           "Sasl Bind In Progress",
	LDAPResultNoSuchAttribute:              "No Such Attribute",
	LDAPResultUndefinedAttributeType:       "Undefined Attribute Type",
	LDAPResultInappropriateMatching:        "Inappropriate Matching",
	LDAPResultConstraintViolation:          "Constraint Violation",
	LDAPResultAttributeOrValueExists:       "Attribute Or Value Exists",
	LDAPResultInvalidAttributeSyntax:       "Invalid Attribute Syntax",
	LDAPResultNoSuchObject:                 "No Such Object",
	LDAPResultAliasProblem:                 "Alias Problem",
	LDAPResultInvalidDNSyntax:              "Invalid DN Syntax",
	LDAPResultAliasDereferencingProblem:    "Alias Dereferencing Problem",
	LDAPResultInappropriateAuthentication:  "Inappropriate Authentication",
	LDAPResultInvalidCredentials:           "Invalid Credentials",
	LDAPResultInsufficientAccessRights:     "Insufficient Access Rights",
	LDAPResultBusy:                         "Busy",
	LDAPResultUnavailable:                  "Unavailable",
	LDAPResultUnwillingToPerform:           "Unwilling To Perform",
	LDAPResultLoopDetect:                   "Loop Detect",
	LDAPResultNamingViolation:              "Naming Violation",
	LDAPResultObjectClassViolation:         "Object Class Violation",
	LDAPResultNotAllowedOnNonLeaf:          "Not Allowed On Non Leaf",
	LDAPResultNotAllowedOnRDN:              "Not Allowed On RDN",
	LDAPResultEntryAlreadyExists:           "Entry Already Exists",
	LDAPResultObjectClassModsProhibited:    "Object Class Mods Prohibited",
	LDAPResultAffectsMultipleDSAs:          "Affects Multiple DSAs",
	LDAPResultOther:                        "Other",
}

// Other LDAP constants
const (
	LDAPBindAuthSimple = 0
	LDAPBindAuthSASL   = 3
)

type LDAPResultCode uint8

type (
	Attribute      = ldap.Attribute
	AddRequest     = ldap.AddRequest
	DeleteRequest  = ldap.ModifyRequest
	CompareRequest = ldap.CompareRequest
)

type ModifyDNRequest struct {
	DN           string
	NewRDN       string
	DeleteOldRDN bool
	NewSuperior  string
}

type ExtendedRequest struct {
	Name  string
	Value string
}

func DebugBinaryFile(fileName string) error {
	return ldap.DebugBinaryFile(fileName)
}

type Error struct {
	Err        error
	ResultCode LDAPResultCode
}

func (e *Error) Error() string {
	return fmt.Sprintf("LDAP Result Code %d %q: %s", e.ResultCode, LDAPResultCodeMap[e.ResultCode], e.Err.Error())
}

func NewError(resultCode LDAPResultCode, err error) error {
	return &Error{ResultCode: resultCode, Err: err}
}

func getLDAPResultCode(packet *ber.Packet) (code LDAPResultCode, description string) {
	if len(packet.Children) >= 2 {
		response := packet.Children[1]
		if response.ClassType == ber.ClassApplication && response.TagType == ber.TypeConstructed && len(response.Children) == 3 {
			return LDAPResultCode(response.Children[0].Value.(int64)), response.Children[2].Value.(string)
		}
	}

	return ErrorNetwork, "Invalid packet format"
}
