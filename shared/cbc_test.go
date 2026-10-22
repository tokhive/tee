package shared

import (
	"bytes"
	"testing"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
)

func TestTLS12CBCRecordDigestBindsDirectionSequenceAndWireBytes(t *testing.T) {
	record := &teeproto.TLSRecord{
		Header: []byte{23, 3, 3, 0, 3}, Payload: []byte{1, 2, 3}, SeqNum: 1,
	}
	base, err := TLS12CBCRecordDigest(TLS12CBCRequestDigestDomain, []*teeproto.TLSRecord{record})
	if err != nil {
		t.Fatal(err)
	}
	response, err := TLS12CBCRecordDigest(TLS12CBCResponseDigestDomain, []*teeproto.TLSRecord{record})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(base, response) {
		t.Fatal("request and response digest domains collided")
	}

	mutations := map[string]*teeproto.TLSRecord{
		"sequence": {Header: []byte{23, 3, 3, 0, 3}, Payload: []byte{1, 2, 3}, SeqNum: 2},
		"header":   {Header: []byte{21, 3, 3, 0, 3}, Payload: []byte{1, 2, 3}, SeqNum: 1},
		"payload":  {Header: []byte{23, 3, 3, 0, 3}, Payload: []byte{1, 2, 4}, SeqNum: 1},
	}
	for name, mutation := range mutations {
		t.Run(name, func(t *testing.T) {
			digest, digestErr := TLS12CBCRecordDigest(TLS12CBCRequestDigestDomain, []*teeproto.TLSRecord{mutation})
			if digestErr != nil {
				t.Fatal(digestErr)
			}
			if bytes.Equal(base, digest) {
				t.Fatal("mutation did not change the digest")
			}
		})
	}
}

func TestTLS12CBCRecordDigestRejectsInvalidWireShape(t *testing.T) {
	tests := []*teeproto.TLSRecord{
		nil,
		{Header: []byte{23, 3, 3, 0}, Payload: nil},
		{Header: []byte{23, 3, 3, 0, 2}, Payload: []byte{1}},
	}
	for i, record := range tests {
		if _, err := TLS12CBCRecordDigest(TLS12CBCRequestDigestDomain, []*teeproto.TLSRecord{record}); err == nil {
			t.Fatalf("invalid record %d was accepted", i)
		}
	}
	if _, err := TLS12CBCRecordDigest("invalid", nil); err == nil {
		t.Fatal("invalid digest domain was accepted")
	}
}
