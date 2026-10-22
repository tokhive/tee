package shared

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
)

const (
	TLS12CBCRequestDigestDomain  = "reclaim.tls12-cbc.request-records.v1\x00"
	TLS12CBCResponseDigestDomain = "reclaim.tls12-cbc.response-records.v1\x00"
)

// TLS12CBCRecordDigest hashes exact TLS records in their authenticated order.
// The caller supplies authoritative sequence numbers; client-supplied values
// must not be trusted for response records.
func TLS12CBCRecordDigest(domain string, records []*teeproto.TLSRecord) ([]byte, error) {
	if domain != TLS12CBCRequestDigestDomain && domain != TLS12CBCResponseDigestDomain {
		return nil, fmt.Errorf("invalid TLS 1.2 CBC digest domain")
	}
	h := sha256.New()
	_, _ = h.Write([]byte(domain))
	var encoded [8]byte
	for i, record := range records {
		if record == nil || len(record.GetHeader()) != 5 {
			return nil, fmt.Errorf("TLS record %d has invalid header", i)
		}
		wireLength := int(record.GetHeader()[3])<<8 | int(record.GetHeader()[4])
		if wireLength != len(record.GetPayload()) {
			return nil, fmt.Errorf("TLS record %d length mismatch", i)
		}
		binary.BigEndian.PutUint64(encoded[:], record.GetSeqNum())
		_, _ = h.Write(encoded[:])
		_, _ = h.Write(record.GetHeader())
		binary.BigEndian.PutUint32(encoded[:4], uint32(len(record.GetPayload())))
		_, _ = h.Write(encoded[:4])
		_, _ = h.Write(record.GetPayload())
	}
	return h.Sum(nil), nil
}
