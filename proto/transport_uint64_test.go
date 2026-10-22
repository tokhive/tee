package teeproto

import (
	"encoding/hex"
	"fmt"
	"math"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

func TestOTLifetimeUint64WireBoundaries(t *testing.T) {
	tests := []struct {
		name string
		new  func(uint64) proto.Message
		get  func(proto.Message) uint64
		tag  protoreflect.FieldNumber
		wire map[uint64]string
	}{
		{
			name: "resume_next_index",
			new:  func(v uint64) proto.Message { return &OTResumeRequest{NextIndex: v} },
			get:  func(m proto.Message) uint64 { return m.(*OTResumeRequest).GetNextIndex() },
			tag:  2,
			wire: boundaryGolden("10"),
		},
		{
			name: "complete_pool_size",
			new:  func(v uint64) proto.Message { return &OTPrecomputeComplete{PoolSize: v} },
			get:  func(m proto.Message) uint64 { return m.(*OTPrecomputeComplete).GetPoolSize() },
			tag:  1,
			wire: boundaryGolden("08"),
		},
		{
			name: "online_ot_start_index",
			new:  func(v uint64) proto.Message { return &OPRFOnlineFull{OtStartIndex: v} },
			get:  func(m proto.Message) uint64 { return m.(*OPRFOnlineFull).GetOtStartIndex() },
			tag:  10,
			wire: boundaryGolden("50"),
		},
	}
	values := []uint64{math.MaxUint32 - 1, math.MaxUint32, math.MaxUint32 + 1, math.MaxUint64}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, value := range values {
				t.Run(fmt.Sprint(value), func(t *testing.T) {
					encoded, err := proto.Marshal(tc.new(value))
					if err != nil {
						t.Fatal(err)
					}
					if got := hex.EncodeToString(encoded); got != tc.wire[value] {
						t.Fatalf("wire=%s, want %s", got, tc.wire[value])
					}
					decoded := tc.new(0)
					if err := proto.Unmarshal(encoded, decoded); err != nil {
						t.Fatal(err)
					}
					if got := tc.get(decoded); got != value {
						t.Fatalf("round trip=%d, want %d", got, value)
					}

					if value <= math.MaxUint32 {
						oldWire := marshalLegacyUint32(t, tc.tag, uint32(value))
						if string(encoded) != string(oldWire) {
							t.Fatalf("new wire %x differs from old uint32 wire %x", encoded, oldWire)
						}
						return
					}
					oldValue := readLegacyUint32(t, tc.tag, encoded)
					if uint64(oldValue) == value {
						t.Fatalf("old uint32 reader unexpectedly preserved %d", value)
					}
				})
			}
		})
	}
}

func boundaryGolden(tag string) map[uint64]string {
	return map[uint64]string{
		math.MaxUint32 - 1: tag + "feffffff0f",
		math.MaxUint32:     tag + "ffffffff0f",
		math.MaxUint32 + 1: tag + "8080808010",
		math.MaxUint64:     tag + "ffffffffffffffffff01",
	}
}

func marshalLegacyUint32(t *testing.T, number protoreflect.FieldNumber, value uint32) []byte {
	t.Helper()
	message, field := legacyUint32Message(t, number)
	message.Set(field, protoreflect.ValueOfUint32(value))
	encoded, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func readLegacyUint32(t *testing.T, number protoreflect.FieldNumber, encoded []byte) uint32 {
	t.Helper()
	message, field := legacyUint32Message(t, number)
	if err := proto.Unmarshal(encoded, message); err != nil {
		t.Fatal(err)
	}
	return uint32(message.Get(field).Uint())
}

func legacyUint32Message(t *testing.T, number protoreflect.FieldNumber) (*dynamicpb.Message, protoreflect.FieldDescriptor) {
	t.Helper()
	label := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL
	kind := descriptorpb.FieldDescriptorProto_TYPE_UINT32
	file, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Syntax:  new("proto3"),
		Name:    new("legacy.proto"),
		Package: new("legacy"),
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: new("Legacy"),
			Field: []*descriptorpb.FieldDescriptorProto{{
				Name: new("value"), Number: new(int32(number)), Label: &label, Type: &kind,
			}},
		}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := file.Messages().ByName("Legacy")
	field := descriptor.Fields().ByNumber(number)
	return dynamicpb.NewMessage(descriptor), field
}
