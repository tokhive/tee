package teeproto

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

func TestTLS12CBCCapabilityIsAdditiveForPreCBCClients(t *testing.T) {
	legacy, fields := legacyRequestConnectionMessage(t)
	legacy.Set(fields.ByNumber(1), protoreflect.ValueOfString("example.com"))
	legacy.Set(fields.ByNumber(2), protoreflect.ValueOfInt32(443))
	legacy.Set(fields.ByNumber(3), protoreflect.ValueOfString("example.com"))
	legacy.Mutable(fields.ByNumber(4)).List().Append(protoreflect.ValueOfString("http/1.1"))
	legacy.Set(fields.ByNumber(5), protoreflect.ValueOfString("1.2"))
	legacy.Set(fields.ByNumber(6), protoreflect.ValueOfString("0xc02f"))
	legacyWire, err := (proto.MarshalOptions{Deterministic: true}).Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	var decoded RequestConnection
	if err := proto.Unmarshal(legacyWire, &decoded); err != nil {
		t.Fatalf("new TEE rejected pre-CBC RequestConnection: %v", err)
	}
	if decoded.GetSupportsTls12Cbc() {
		t.Fatal("absent pre-CBC capability decoded as enabled")
	}
	if decoded.GetHostname() != "example.com" || decoded.GetPort() != 443 || decoded.GetSni() != "example.com" ||
		len(decoded.GetAlpn()) != 1 || decoded.GetAlpn()[0] != "http/1.1" ||
		decoded.GetForceTlsVersion() != "1.2" || decoded.GetForceCipherSuite() != "0xc02f" {
		t.Fatalf("new TEE changed pre-CBC request fields: %+v", &decoded)
	}

	legacyEquivalentWire, err := (proto.MarshalOptions{Deterministic: true}).Marshal(&RequestConnection{
		Hostname: "example.com", Port: 443, Sni: "example.com", Alpn: []string{"http/1.1"},
		ForceTlsVersion: "1.2", ForceCipherSuite: "0xc02f",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(legacyEquivalentWire, legacyWire) {
		t.Fatalf("default-false capability changed legacy wire: got %x, want %x", legacyEquivalentWire, legacyWire)
	}

	newWire, err := (proto.MarshalOptions{Deterministic: true}).Marshal(&RequestConnection{
		Hostname: "example.com", Port: 443, Sni: "example.com", Alpn: []string{"http/1.1"},
		ForceTlsVersion: "1.2", ForceCipherSuite: "0xc02f", SupportsTls12Cbc: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	legacyReceiver, legacyFields := legacyRequestConnectionMessage(t)
	if err := proto.Unmarshal(newWire, legacyReceiver); err != nil {
		t.Fatalf("pre-CBC TEE rejected additive RequestConnection: %v", err)
	}
	if got := legacyReceiver.Get(legacyFields.ByNumber(1)).String(); got != "example.com" {
		t.Fatalf("legacy hostname = %q", got)
	}
	if got := int32(legacyReceiver.Get(legacyFields.ByNumber(2)).Int()); got != 443 {
		t.Fatalf("legacy port = %d", got)
	}
	if got := legacyReceiver.Get(legacyFields.ByNumber(3)).String(); got != "example.com" {
		t.Fatalf("legacy SNI = %q", got)
	}
	if got := legacyReceiver.Get(legacyFields.ByNumber(4)).List(); got.Len() != 1 || got.Get(0).String() != "http/1.1" {
		t.Fatalf("legacy ALPN = %v", got)
	}
	if got := legacyReceiver.Get(legacyFields.ByNumber(5)).String(); got != "1.2" {
		t.Fatalf("legacy TLS version = %q", got)
	}
	if got := legacyReceiver.Get(legacyFields.ByNumber(6)).String(); got != "0xc02f" {
		t.Fatalf("legacy cipher suite = %q", got)
	}
}

func TestTLS12CBCHandshakeBindingIsAdditiveForPreCBCClients(t *testing.T) {
	legacy, fields := legacyHandshakeCompleteMessage(t)
	legacy.Set(fields.ByNumber(1), protoreflect.ValueOfBool(true))
	legacy.Mutable(fields.ByNumber(2)).List().Append(protoreflect.ValueOfBytes([]byte{1, 2, 3}))
	legacy.Set(fields.ByNumber(3), protoreflect.ValueOfUint32(0xc02f))
	legacyWire, err := (proto.MarshalOptions{Deterministic: true}).Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}

	currentLegacyWire, err := (proto.MarshalOptions{Deterministic: true}).Marshal(&HandshakeComplete{
		Success: true, CertificateChain: [][]byte{{1, 2, 3}}, CipherSuite: 0xc02f,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(currentLegacyWire, legacyWire) {
		t.Fatalf("empty CBC binding changed legacy handshake wire: got %x, want %x", currentLegacyWire, legacyWire)
	}

	currentCBCWire, err := (proto.MarshalOptions{Deterministic: true}).Marshal(&HandshakeComplete{
		Success: true, CertificateChain: [][]byte{{1, 2, 3}}, CipherSuite: 0xc013,
		Tls12CbcBinding: &TLS12CBCSessionBinding{
			ContractVersion: 1, CipherSuite: 0xc013,
			RecordMode:     TLS12CBCRecordMode_TLS12_CBC_RECORD_MODE_MAC_THEN_ENCRYPT,
			SessionBinding: bytes.Repeat([]byte{7}, 32),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	legacyReceiver, legacyFields := legacyHandshakeCompleteMessage(t)
	if err := proto.Unmarshal(currentCBCWire, legacyReceiver); err != nil {
		t.Fatalf("pre-CBC client rejected additive handshake binding: %v", err)
	}
	if !legacyReceiver.Get(legacyFields.ByNumber(1)).Bool() ||
		legacyReceiver.Get(legacyFields.ByNumber(3)).Uint() != 0xc013 {
		t.Fatalf("pre-CBC client lost legacy handshake fields: %v", legacyReceiver)
	}
}

func legacyRequestConnectionMessage(t *testing.T) (*dynamicpb.Message, protoreflect.FieldDescriptors) {
	t.Helper()
	optional := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL
	repeated := descriptorpb.FieldDescriptorProto_LABEL_REPEATED
	stringType := descriptorpb.FieldDescriptorProto_TYPE_STRING
	int32Type := descriptorpb.FieldDescriptorProto_TYPE_INT32
	file, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name:    new("legacy_request_connection.proto"),
		Package: new("legacy"),
		Syntax:  new("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: new("RequestConnection"),
			Field: []*descriptorpb.FieldDescriptorProto{
				{Name: new("hostname"), Number: new(int32(1)), Label: &optional, Type: &stringType},
				{Name: new("port"), Number: new(int32(2)), Label: &optional, Type: &int32Type},
				{Name: new("sni"), Number: new(int32(3)), Label: &optional, Type: &stringType},
				{Name: new("alpn"), Number: new(int32(4)), Label: &repeated, Type: &stringType},
				{Name: new("force_tls_version"), Number: new(int32(5)), Label: &optional, Type: &stringType},
				{Name: new("force_cipher_suite"), Number: new(int32(6)), Label: &optional, Type: &stringType},
			},
		}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := file.Messages().ByName("RequestConnection")
	return dynamicpb.NewMessage(descriptor), descriptor.Fields()
}

func legacyHandshakeCompleteMessage(t *testing.T) (*dynamicpb.Message, protoreflect.FieldDescriptors) {
	t.Helper()
	optional := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL
	repeated := descriptorpb.FieldDescriptorProto_LABEL_REPEATED
	boolType := descriptorpb.FieldDescriptorProto_TYPE_BOOL
	bytesType := descriptorpb.FieldDescriptorProto_TYPE_BYTES
	uint32Type := descriptorpb.FieldDescriptorProto_TYPE_UINT32
	file, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name:    new("legacy_handshake_complete.proto"),
		Package: new("legacy"),
		Syntax:  new("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: new("HandshakeComplete"),
			Field: []*descriptorpb.FieldDescriptorProto{
				{Name: new("success"), Number: new(int32(1)), Label: &optional, Type: &boolType},
				{Name: new("certificate_chain"), Number: new(int32(2)), Label: &repeated, Type: &bytesType},
				{Name: new("cipher_suite"), Number: new(int32(3)), Label: &optional, Type: &uint32Type},
			},
		}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := file.Messages().ByName("HandshakeComplete")
	return dynamicpb.NewMessage(descriptor), descriptor.Fields()
}
