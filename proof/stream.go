package proof

import (
	"crypto/sha256"
	"encoding"
	"hash"
)

// ResponseStreamDomain is the prefix mixed into every response digest so that a
// response digest can never be replayed as, say, a job spec digest.
const ResponseStreamDomain = "TokenHive.Response.v1"

// StreamingHasher incrementally digests a streamed response body.
//
// The digest is SHA-256 over:
//
//	"TokenHive.Response.v1" || job_id || response_bytes
//
// Because SHA-256 is sequential, feeding chunks in arrival order produces
// exactly the digest of the concatenation — no separate tree is needed, and a
// verifier replaying a captured transcript reproduces the same value.
//
// Chunk boundaries are deliberately not folded into the digest. A response is
// the same response whether the transport delivered it in ten SSE events or
// one, and binding framing would make the proof brittle to harmless
// re-chunking. Framing is attested separately: ChunkCount and ResponseBytes
// live inside the signed receipt, so they cannot be altered without breaking
// the signature.
type StreamingHasher struct {
	jobID  []byte
	h      hash.Hash
	chunks uint64
	bytes  uint64
}

// NewStreamingHasher returns a hasher bound to one job. The job ID is part of
// the digest prefix, so a receipt for one job can never be presented as proof
// of another job's response.
func NewStreamingHasher(jobID []byte) *StreamingHasher {
	s := &StreamingHasher{
		jobID: append([]byte(nil), jobID...),
		h:     sha256.New(),
	}
	s.Reset()
	return s
}

// Write absorbs the next bytes of the response body. It implements io.Writer so
// it can be wrapped around a transport reader without buffering the body.
func (s *StreamingHasher) Write(p []byte) (int, error) {
	n, err := s.h.Write(p)
	s.bytes += uint64(n)
	return n, err
}

// WriteChunk absorbs one complete SSE chunk and advances the chunk counter.
// Empty writes still count: a heartbeat chunk is part of the observed stream.
func (s *StreamingHasher) WriteChunk(p []byte) error {
	if _, err := s.Write(p); err != nil {
		return err
	}
	s.chunks++
	return nil
}

// ChunkCount returns how many WriteChunk calls have been observed.
func (s *StreamingHasher) ChunkCount() uint64 { return s.chunks }

// BytesWritten returns how many response bytes have been absorbed.
func (s *StreamingHasher) BytesWritten() uint64 { return s.bytes }

// Sum returns the digest of everything written so far without disturbing the
// hasher, so it can be called repeatedly to checkpoint a long stream.
func (s *StreamingHasher) Sum() [32]byte {
	var out [32]byte
	copy(out[:], s.clone().Sum(nil))
	return out
}

// clone snapshots the underlying hash state via encoding.BinaryMarshaler,
// which every hash in the standard library implements. Finalising a hash
// consumes its state, so checkpointing requires a copy.
func (s *StreamingHasher) clone() hash.Hash {
	marshaler, ok := s.h.(encoding.BinaryMarshaler)
	if !ok {
		panic("proof: hash implementation does not support state cloning")
	}
	state, err := marshaler.MarshalBinary()
	if err != nil {
		panic("proof: snapshot hash state: " + err.Error())
	}
	clone := sha256.New()
	if err := clone.(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err != nil {
		panic("proof: restore hash state: " + err.Error())
	}
	return clone
}

// Reset returns the hasher to its initial state, keeping the same job binding.
func (s *StreamingHasher) Reset() {
	s.h.Reset()
	s.h.Write([]byte(ResponseStreamDomain))
	s.h.Write(s.jobID)
	s.chunks = 0
	s.bytes = 0
}

// HashResponseStream recomputes a response digest from a full transcript. It is
// the verification-side counterpart of StreamingHasher and must agree with it
// for any sequence of chunks.
func HashResponseStream(jobID []byte, chunks [][]byte) [32]byte {
	h := NewStreamingHasher(jobID)
	for _, chunk := range chunks {
		if err := h.WriteChunk(chunk); err != nil {
			// sha256 never returns an error from Write; this is unreachable.
			panic("proof: hash response stream: " + err.Error())
		}
	}
	return h.Sum()
}
