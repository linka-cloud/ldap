package ldap

import (
	"context"
	"errors"
	"fmt"
	"net"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func HandleAddRequest(ctx context.Context, req *ber.Packet, fns map[string]Adder) (resultCode LDAPResultCode) {
	if len(req.Children) != 2 {
		return LDAPResultProtocolError
	}
	var ok bool
	addReq := AddRequest{}
	addReq.DN, ok = req.Children[0].Value.(string)
	if !ok {
		return LDAPResultProtocolError
	}
	addReq.Attributes = []Attribute{}
	for _, attr := range req.Children[1].Children {
		if len(attr.Children) != 2 {
			return LDAPResultProtocolError
		}

		a := Attribute{}
		a.Type, ok = attr.Children[0].Value.(string)
		if !ok {
			return LDAPResultProtocolError
		}
		a.Vals = []string{}
		for _, val := range attr.Children[1].Children {
			v, ok := val.Value.(string)
			if !ok {
				return LDAPResultProtocolError
			}
			a.Vals = append(a.Vals, v)
		}
		addReq.Attributes = append(addReq.Attributes, a)
	}
	fnNames := []string{}
	for k := range fns {
		fnNames = append(fnNames, k)
	}
	fn := routeFunc(addReq.DN, fnNames)
	resultCode, err := fns[fn].Add(ctx, addReq)
	if err != nil {
		Log.Printf("AddFn Error %s", err.Error())
		return LDAPResultOperationsError
	}
	return resultCode
}

func HandleDeleteRequest(ctx context.Context, req *ber.Packet, fns map[string]Deleter) (resultCode LDAPResultCode) {
	deleteDN := ber.DecodeString(req.Data.Bytes())
	fnNames := []string{}
	for k := range fns {
		fnNames = append(fnNames, k)
	}
	fn := routeFunc(deleteDN, fnNames)
	resultCode, err := fns[fn].Delete(ctx, deleteDN)
	if err != nil {
		Log.Printf("DeleteFn Error %s", err.Error())
		return LDAPResultOperationsError
	}
	return resultCode
}

func HandleModifyRequest(ctx context.Context, req *ber.Packet, fns map[string]Modifier) (resultCode LDAPResultCode) {
	if len(req.Children) != 2 {
		return LDAPResultProtocolError
	}
	var ok bool
	modReq := ModifyRequest{}
	modReq.DN, ok = req.Children[0].Value.(string)
	if !ok {
		return LDAPResultProtocolError
	}
	for _, change := range req.Children[1].Children {
		if len(change.Children) != 2 {
			return LDAPResultProtocolError
		}
		attr := PartialAttribute{}
		attrs := change.Children[1].Children
		if len(attrs) != 2 {
			return LDAPResultProtocolError
		}
		attr.Type, ok = attrs[0].Value.(string)
		if !ok {
			return LDAPResultProtocolError
		}
		for _, val := range attrs[1].Children {
			v, ok := val.Value.(string)
			if !ok {
				return LDAPResultProtocolError
			}
			attr.Vals = append(attr.Vals, v)
		}
		op, ok := change.Children[0].Value.(int64)
		if !ok {
			return LDAPResultProtocolError
		}
		switch op {
		default:
			Log.Printf("Unrecognized Modify attribute %d", op)
			return LDAPResultProtocolError
		case AddAttribute:
			modReq.Add(attr.Type, attr.Vals)
		case DeleteAttribute:
			modReq.Delete(attr.Type, attr.Vals)
		case ReplaceAttribute:
			modReq.Replace(attr.Type, attr.Vals)
		}
	}
	fnNames := []string{}
	for k := range fns {
		fnNames = append(fnNames, k)
	}
	fn := routeFunc(modReq.DN, fnNames)
	resultCode, err := fns[fn].Modify(ctx, modReq)
	if err != nil {
		Log.Printf("ModifyFn Error %s", err.Error())
		return LDAPResultOperationsError
	}
	return resultCode
}

func HandleCompareRequest(ctx context.Context, req *ber.Packet, fns map[string]Comparer) (resultCode LDAPResultCode) {
	if len(req.Children) != 2 {
		return LDAPResultProtocolError
	}
	var ok bool
	compReq := CompareRequest{}
	compReq.DN, ok = req.Children[0].Value.(string)
	if !ok {
		return LDAPResultProtocolError
	}
	ava := req.Children[1]
	if len(ava.Children) != 2 {
		return LDAPResultProtocolError
	}
	compReq.Attribute, ok = ava.Children[0].Value.(string)
	if !ok {
		return LDAPResultProtocolError
	}
	compReq.Value, ok = ava.Children[1].Value.(string)
	if !ok {
		return LDAPResultProtocolError
	}
	fnNames := []string{}
	for k := range fns {
		fnNames = append(fnNames, k)
	}
	fn := routeFunc(compReq.DN, fnNames)
	resultCode, err := fns[fn].Compare(ctx, compReq)
	if err != nil {
		Log.Printf("CompareFn Error %s", err.Error())
		return LDAPResultOperationsError
	}
	return resultCode
}

func HandleExtendedRequest(ctx context.Context, req *ber.Packet, controls []Control, fns map[string]Extender, conn net.Conn, messageID uint64) (resultErr error) {
	defer func() {
		if r := recover(); r != nil {
			resultErr = NewError(LDAPResultOperationsError, fmt.Errorf("Extended function panic: %s", r))
		}
	}()

	if len(req.Children) != 1 && len(req.Children) != 2 {
		return NewError(LDAPResultProtocolError, errors.New("Bad extended request"))
	}
	name := ber.DecodeString(req.Children[0].Data.Bytes())
	var val *ber.Packet
	if len(req.Children) == 2 {
		val = req.Children[1]
	}
	extReq := ExtendedRequest{name, val, controls}
	fnNames := []string{}
	for k := range fns {
		fnNames = append(fnNames, k)
	}
	fn := routeFunc("", fnNames)
	res, err := fns[fn].Extended(ctx, extReq)
	if err != nil {
		Log.Printf("ExtendedFn Error %s", err.Error())
		return NewError(LDAPResultOperationsError, err)
	}
	responsePacket := encodeExtendedResponse(messageID, name, res)
	if err := sendPacket(conn, responsePacket); err != nil {
		Log.Printf("sendPacket error %s", err.Error())
		return NewError(LDAPResultOperationsError, err)
	}

	return nil
}

func encodeExtendedResponse(messageID uint64, requestName string, res ExtendedResponse) *ber.Packet {
	responsePacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	responsePacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "Message ID"))
	response := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(ApplicationExtendedResponse), nil, ApplicationMap[ApplicationExtendedResponse])
	response.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, uint64(res.ResultCode), "resultCode: "))
	response.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN: "))
	response.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, LDAPResultCodeMap[res.ResultCode], "errorMessage: "))
	responseName := res.Name
	if responseName == "" {
		responseName = requestName
	}
	response.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 10, responseName, "responseName: "))
	if res.Value != nil {
		if res.Value.ClassType == ber.ClassContext && res.Value.Tag == 11 {
			response.AppendChild(res.Value)
		} else {
			response.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 11, string(res.Value.Bytes()), "responseValue: "))
		}
	}
	responsePacket.AppendChild(response)
	if len(res.Controls) > 0 {
		responsePacket.AppendChild(encodeControls(res.Controls))
	}
	return responsePacket
}

func HandleModifyDNRequest(ctx context.Context, req *ber.Packet, fns map[string]ModifyDNr) (resultCode LDAPResultCode) {
	if len(req.Children) != 3 && len(req.Children) != 4 {
		return LDAPResultProtocolError
	}
	var ok bool
	mdnReq := ModifyDNRequest{}
	mdnReq.DN, ok = req.Children[0].Value.(string)
	if !ok {
		return LDAPResultProtocolError
	}
	mdnReq.NewRDN, ok = req.Children[1].Value.(string)
	if !ok {
		return LDAPResultProtocolError
	}
	mdnReq.DeleteOldRDN, ok = req.Children[2].Value.(bool)
	if !ok {
		return LDAPResultProtocolError
	}
	if len(req.Children) == 4 {
		mdnReq.NewSuperior, ok = req.Children[3].Value.(string)
		if !ok {
			return LDAPResultProtocolError
		}
	}
	fnNames := []string{}
	for k := range fns {
		fnNames = append(fnNames, k)
	}
	fn := routeFunc(mdnReq.DN, fnNames)
	resultCode, err := fns[fn].ModifyDN(ctx, mdnReq)
	if err != nil {
		Log.Printf("ModifyDN Error %s", err.Error())
		return LDAPResultOperationsError
	}
	return resultCode
}
