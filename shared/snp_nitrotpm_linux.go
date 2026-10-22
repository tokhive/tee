//go:build linux && !mobile

package shared

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

// Pure-Go port of aws/NitroTPM-Tools `nitro-tpm-attest` (avoids bundling the
// Rust binary + its libtss2 C closure into the minimal TEE image). It drives the
// TPM2 "AWS NSM vendor command" (0x20000001): load the RSA-2048 Endorsement Key,
// define an NV "message buffer", write the CBOR-encoded NSM Attestation request,
// issue the vendor command (the Nitro hypervisor signs and writes the document
// back into the buffer), then read it out. The NV ops use a salted+encrypted
// HMAC session (go-tpm direct API); the vendor command uses a hand-built salted
// HMAC auth area (the vendor command is not a standard TPM2 command).
const (
	tpm2VendorAWSNSMRequest = 0x20000001
	tpmSTSessions           = 0x8002 // TPM_ST_SESSIONS
	nsmMessageBufferSize    = 8192
)

// GenerateCombinedAWSAttestation returns the AWS combined envelope. New bases
// use the measured root broker to add the same-guest SEV2 proof; old bases keep
// producing the legacy envelope until strict verification is enabled.
func GenerateCombinedAWSAttestation(spkiDER, appHash []byte) ([]byte, error) {
	return generateCombinedAWS(spkiDER, appHash, nil)
}

// generateCombinedAWS binds the given blob (raw SPKI for the cert path, or the
// nonce commitment for the claim path) into both the NitroTPM user_data and the
// SEV report_data, and carries the presentable nonces (if any) in the envelope.
func generateCombinedAWS(bound, appHash []byte, nonces []string) ([]byte, error) {
	snpAttestMu.Lock()
	defer snpAttestMu.Unlock()

	cacheKey := snpAttestCacheKey("aws:"+CurrentSNPAttestationType(), bound, appHash, nonces)
	if att, ok := snpAttestCacheGet(cacheKey); ok {
		return att, nil
	}
	if cErr := snpDeviceInCooldown(); cErr != nil {
		return nil, cErr
	}
	envBytes, err := generateCombinedAWSUncached(bound, appHash, nonces)
	snpRecordDeviceResult(err)
	if err != nil {
		return nil, err
	}
	snpAttestCachePut(cacheKey, envBytes)
	return envBytes, nil
}

// generateCombinedAWSUncached does the NitroTPM + SEV device work; the caller
// holds snpAttestMu and owns caching + the post-failure cooldown.
func generateCombinedAWSUncached(bound, appHash []byte, nonces []string) ([]byte, error) {
	var eventLog []byte
	var err error
	if secureBootAttestationEnabled() {
		eventLog, err = readSecureBootEventLog()
		if err != nil {
			return nil, err
		}
	}
	if hasSNPAttestationBroker() {
		evidence, err := requestAWSBrokerEvidence(bound, appHash)
		if err != nil {
			return nil, err
		}
		return cbor.Marshal(combinedEnvelope{
			AppHash:  appHash,
			NitroTPM: evidence.nitroTPM,
			SEV:      evidence.legacySEV,
			SEV2:     evidence.sev2,
			EventLog: eventLog,
			Nonces:   nonces,
		})
	}

	// Legacy bases expose the attestation devices directly to the app. Keep
	// this producer during expansion so old bases can run upgraded app bundles;
	// v2-enforcing verifiers reject its envelope because it has no SEV2 field.
	bind := sha512.Sum512(bound)
	doc, err := RequestNitroTPMDocument(bind[:], nil, nil)
	if err != nil {
		return nil, fmt.Errorf("nitrotpm document: %w", err)
	}
	report, err := GenerateSEVSNPAttestation(bind)
	if err != nil {
		return nil, fmt.Errorf("sev report: %w", err)
	}
	envBytes, err := cbor.Marshal(combinedEnvelope{AppHash: appHash, NitroTPM: doc, SEV: report, EventLog: eventLog, Nonces: nonces})
	if err != nil {
		return nil, err
	}
	return envBytes, nil
}

// RequestNitroTPMDocument returns the signed NitroTPM attestation document
// (COSE_Sign1/CBOR) carrying the given optional user_data/nonce/public_key.
func RequestNitroTPMDocument(userData, nonce, publicKey []byte) ([]byte, error) {
	// Raw device, NOT the resource manager: the AWS NSM vendor command goes
	// straight to the TPM (the kernel RM mangles/rejects it). Matches the Rust
	// tool's default TPM_DEVICE=/dev/tpm0.
	rwc, err := linuxtpm.Open("/dev/tpm0")
	if err != nil {
		return nil, fmt.Errorf("open tpm: %w", err)
	}
	defer rwc.Close()

	// 1. Endorsement key (transient; one transport so no persistence needed).
	ekPrimary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(rsaEKTemplate()),
	}.Execute(rwc)
	if err != nil {
		return nil, fmt.Errorf("create EK: %w", err)
	}
	ekHandle := ekPrimary.ObjectHandle
	defer tpm2.FlushContext{FlushHandle: ekHandle}.Execute(rwc)

	ekPub, err := ekPrimary.OutPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("EK public: %w", err)
	}
	ekRSA, err := ekRSAPublicKey(ekPub)
	if err != nil {
		return nil, err
	}

	// 2. CBOR-encode the NSM Attestation request (externally-tagged enum).
	reqCBOR, err := encodeNSMAttestationRequest(userData, nonce, publicKey)
	if err != nil {
		return nil, fmt.Errorf("encode NSM request: %w", err)
	}

	// 3. Random NV auth (64B). Define the NV message buffer + write the request
	// under a salted+encrypted HMAC session salted to the EK.
	nvAuth := make([]byte, sha512.Size)
	if _, err := rand.Read(nvAuth); err != nil {
		return nil, err
	}
	nvIndex := tpm2.TPMHandle(0x01800000) // owner-definable NV range (below the TCG-reserved 0x01C0xxxx)

	nvPublic := tpm2.TPMSNVPublic{
		NVIndex: nvIndex,
		NameAlg: tpm2.TPMAlgSHA512,
		Attributes: tpm2.TPMANV{
			AuthRead:  true,
			AuthWrite: true,
			NT:        tpm2.TPMNTOrdinary,
		},
		DataSize: nsmMessageBufferSize,
	}

	// Owner-authorized define; NV index auth via password. No parameter
	// encryption (it's bus confidentiality only and trips NVDefineSpace, which
	// has no response parameters). The vendor command does its own salted HMAC.
	if _, err := (tpm2.NVDefineSpace{
		AuthHandle: tpm2.TPMRHOwner,
		Auth:       tpm2.TPM2BAuth{Buffer: nvAuth},
		PublicInfo: tpm2.New2B(nvPublic),
	}).Execute(rwc); err != nil {
		return nil, fmt.Errorf("NV define: %w", err)
	}
	// NV index Name (needed for write/read auth + the vendor command cpHash).
	nvNamePtr, err := tpm2.NVName(&nvPublic)
	if err != nil {
		return nil, fmt.Errorf("NV name: %w", err)
	}
	nvName := *nvNamePtr
	defer func() {
		tpm2.NVUndefineSpace{
			AuthHandle: tpm2.TPMRHOwner,
			NVIndex:    tpm2.NamedHandle{Handle: nvIndex, Name: nvName},
		}.Execute(rwc)
	}()

	// Write the request into the buffer (NV index password auth).
	if _, err := (tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{Handle: nvIndex, Name: nvName, Auth: tpm2.PasswordAuth(nvAuth)},
		NVIndex:    tpm2.NamedHandle{Handle: nvIndex, Name: nvName},
		Data:       tpm2.TPM2BMaxNVBuffer{Buffer: reqCBOR},
	}).Execute(rwc); err != nil {
		return nil, fmt.Errorf("NV write: %w", err)
	}

	// Re-read the NV public AFTER the write: the TPM sets TPMA_NV_WRITTEN on
	// first write, which changes the index Name. The vendor command's cpHash
	// binds the current Name, so use the post-write one (not our define-time struct).
	rp, err := (tpm2.NVReadPublic{NVIndex: nvIndex}).Execute(rwc)
	if err != nil {
		return nil, fmt.Errorf("NV read public: %w", err)
	}
	writtenName := rp.NVName.Buffer

	// 4. The vendor command: raw, with a hand-built salted HMAC auth area.
	if err := sendNSMVendorCommand(rwc, ekHandle, ekRSA, nvIndex, writtenName, nvAuth); err != nil {
		return nil, fmt.Errorf("NSM vendor command: %w", err)
	}

	// 5. Read the response in chunks (a single NVRead is capped at the TPM's
	// max NV buffer, typically 1024 bytes).
	wName := tpm2.TPM2BName{Buffer: writtenName}
	const nvChunk = 1024
	var buf []byte
	for off := 0; off < nsmMessageBufferSize; off += nvChunk {
		sz := nvChunk
		if rem := nsmMessageBufferSize - off; rem < sz {
			sz = rem
		}
		rr, err := (tpm2.NVRead{
			AuthHandle: tpm2.AuthHandle{Handle: nvIndex, Name: wName, Auth: tpm2.PasswordAuth(nvAuth)},
			NVIndex:    tpm2.NamedHandle{Handle: nvIndex, Name: wName},
			Size:       uint16(sz),
			Offset:     uint16(off),
		}).Execute(rwc)
		if err != nil {
			return nil, fmt.Errorf("NV read @%d: %w", off, err)
		}
		buf = append(buf, rr.Data.Buffer...)
	}
	return decodeNSMAttestationResponse(buf)
}

// --- EK template + key extraction -----------------------------------------

// rsaEKTemplate is the TCG default RSA-2048 Endorsement Key template (low-range,
// the standard EK with the well-known authPolicy).
func rsaEKTemplate() tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			AdminWithPolicy:     true,
			Restricted:          true,
			Decrypt:             true,
		},
		AuthPolicy: tpm2.TPM2BDigest{Buffer: []byte{
			0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d,
			0x46, 0xa5, 0xd7, 0x24, 0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64,
			0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa,
		}},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &tpm2.TPMSRSAParms{
			Symmetric: tpm2.TPMTSymDefObject{
				Algorithm: tpm2.TPMAlgAES,
				KeyBits:   tpm2.NewTPMUSymKeyBits(tpm2.TPMAlgAES, tpm2.TPMKeyBits(128)),
				Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
			},
			KeyBits: 2048,
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA, &tpm2.TPM2BPublicKeyRSA{
			Buffer: make([]byte, 256),
		}),
	}
}

func ekRSAPublicKey(pub *tpm2.TPMTPublic) (*rsa.PublicKey, error) {
	rsaParms, err := pub.Parameters.RSADetail()
	if err != nil {
		return nil, fmt.Errorf("EK RSA parms: %w", err)
	}
	rsaUnique, err := pub.Unique.RSA()
	if err != nil {
		return nil, fmt.Errorf("EK RSA unique: %w", err)
	}
	mod := new(big.Int).SetBytes(rsaUnique.Buffer)
	exp := int(rsaParms.Exponent)
	if exp == 0 {
		exp = 65537
	}
	return &rsa.PublicKey{N: mod, E: exp}, nil
}

// --- NSM CBOR (externally-tagged serde enum) -------------------------------

// nsmAttestationRequest mirrors aws_nitro_enclaves_nsm_api Request::Attestation.
// A struct (not a map) so CBOR field order matches serde/ciborium declaration
// order (user_data, nonce, public_key); nil fields encode as CBOR null.
type nsmAttestationRequest struct {
	UserData  []byte `cbor:"user_data"`
	Nonce     []byte `cbor:"nonce"`
	PublicKey []byte `cbor:"public_key"`
}

func encodeNSMAttestationRequest(userData, nonce, publicKey []byte) ([]byte, error) {
	// Externally-tagged enum: { "Attestation": { ...fields... } }.
	return cbor.Marshal(map[string]nsmAttestationRequest{
		"Attestation": {UserData: userData, Nonce: nonce, PublicKey: publicKey},
	})
}

func decodeNSMAttestationResponse(data []byte) ([]byte, error) {
	// The NV buffer is padded past the CBOR response; decode the first value and
	// ignore the trailing bytes (cbor.Unmarshal would reject trailing data).
	var outer map[string]cbor.RawMessage
	if err := cbor.NewDecoder(bytes.NewReader(data)).Decode(&outer); err != nil {
		return nil, fmt.Errorf("decode NSM response: %w", err)
	}
	raw, ok := outer["Attestation"]
	if !ok {
		return nil, fmt.Errorf("NSM response is not an Attestation (got keys %v)", keysOf(outer))
	}
	var inner struct {
		Document []byte `cbor:"document"`
	}
	if err := cbor.Unmarshal(raw, &inner); err != nil {
		return nil, fmt.Errorf("decode Attestation response: %w", err)
	}
	if len(inner.Document) == 0 {
		return nil, fmt.Errorf("empty attestation document")
	}
	return inner.Document, nil
}

func keysOf(m map[string]cbor.RawMessage) []string {
	var k []string
	for key := range m {
		k = append(k, key)
	}
	return k
}

// --- raw salted session + vendor command -----------------------------------

func sendNSMVendorCommand(rwc interface {
	Send([]byte) ([]byte, error)
}, ekHandle tpm2.TPMHandle, ekPub *rsa.PublicKey, nvIndex tpm2.TPMHandle, nvName, nvAuth []byte) error {
	// Start a salted HMAC session (null symmetric -> no param encryption), SHA512.
	salt := make([]byte, sha256.Size)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	nonceCaller := make([]byte, sha512.Size)
	if _, err := rand.Read(nonceCaller); err != nil {
		return err
	}
	encryptedSalt, err := encryptSalt(ekPub, salt)
	if err != nil {
		return err
	}
	sessionHandle, nonceTPM, err := rawStartSaltedHMAC(rwc, ekHandle, encryptedSalt, nonceCaller)
	if err != nil {
		return err
	}
	defer rawFlush(rwc, sessionHandle)

	sessionKey := kdfaSHA512(salt, "ATH", nonceTPM, nonceCaller, 512)

	// cpHash = SHA512( commandCode || NV-auth-name || NV-index-name ). Both
	// handles reference the NV index, so its Name appears twice.
	cp := sha512.New()
	binary.Write(cp, binary.BigEndian, uint32(tpm2VendorAWSNSMRequest))
	cp.Write(nvName)
	cp.Write(nvName)
	cpHash := cp.Sum(nil)

	const sessionAttrs = 0x01 // continueSession
	newNonceCaller := make([]byte, sha512.Size)
	if _, err := rand.Read(newNonceCaller); err != nil {
		return err
	}
	authHMAC := computeAuthHMAC(sessionKey, nvAuth, cpHash, newNonceCaller, nonceTPM, sessionAttrs)

	authArea := concat(
		be32(uint32(sessionHandle)),
		be16(uint16(len(newNonceCaller))), newNonceCaller,
		[]byte{sessionAttrs},
		be16(uint16(len(authHMAC))), authHMAC,
	)

	cmd := buildCommand(tpmSTSessions, tpm2VendorAWSNSMRequest,
		concat(be32(uint32(nvIndex)), be32(uint32(nvIndex))), // NV auth + NV index handles
		concat(be32(uint32(len(authArea))), authArea),        // authorizationSize + auth area
		nil)
	rsp, err := rwc.Send(cmd)
	if err != nil {
		return fmt.Errorf("send vendor command: %w", err)
	}
	return checkResponseCode(rsp)
}

// encryptSalt RSA-OAEP-SHA256 encrypts the salt to the EK with label "SECRET\0"
// (TPM spec B.10.2 / the salted-session seed).
func encryptSalt(ekPub *rsa.PublicKey, salt []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, ekPub, salt, []byte("SECRET\x00"))
}

// kdfaSHA512 implements TPM2 KDFa with SHA512: counter-mode HMAC, label as a
// null-terminated string, context = contextU||contextV, bits as a 32-bit BE trailer.
func kdfaSHA512(key []byte, label string, contextU, contextV []byte, bits int) []byte {
	out := make([]byte, 0, (bits+511)/512*sha512.Size)
	n := (bits + 8*sha512.Size - 1) / (8 * sha512.Size)
	for i := 1; i <= n; i++ {
		mac := hmac.New(sha512.New, key)
		binary.Write(mac, binary.BigEndian, uint32(i))
		mac.Write([]byte(label))
		mac.Write([]byte{0})
		mac.Write(contextU)
		mac.Write(contextV)
		binary.Write(mac, binary.BigEndian, uint32(bits))
		out = mac.Sum(out)
	}
	return out[:bits/8]
}

func computeAuthHMAC(sessionKey, authValue, cpHash, nonceCaller, nonceTPM []byte, attrs byte) []byte {
	mac := hmac.New(sha512.New, concat(sessionKey, authValue))
	mac.Write(cpHash)
	mac.Write(nonceCaller)
	mac.Write(nonceTPM)
	mac.Write([]byte{attrs})
	return mac.Sum(nil)
}

func rawStartSaltedHMAC(rwc interface {
	Send([]byte) ([]byte, error)
}, saltKey tpm2.TPMHandle, encryptedSalt, nonceCaller []byte) (tpm2.TPMHandle, []byte, error) {
	const ccStartAuthSession = 0x00000176
	const stNoSessions = 0x8001
	const algNull = 0x0010
	const algSHA512 = 0x000D
	const sessionTypeHMAC = 0x00
	params := concat(
		be16(uint16(len(nonceCaller))), nonceCaller,
		be16(uint16(len(encryptedSalt))), encryptedSalt,
		[]byte{sessionTypeHMAC},
		be16(algNull),   // symmetric.algorithm = NULL
		be16(algSHA512), // authHash
	)
	handles := concat(be32(uint32(saltKey)), be32(0x40000007)) // saltKey, bind=TPM_RH_NULL
	cmd := buildCommand(stNoSessions, ccStartAuthSession, handles, nil, params)
	rsp, err := rwc.Send(cmd)
	if err != nil {
		return 0, nil, err
	}
	body, err := responseBody(rsp)
	if err != nil {
		return 0, nil, err
	}
	if len(body) < 4 {
		return 0, nil, fmt.Errorf("short StartAuthSession response")
	}
	sessionHandle := tpm2.TPMHandle(binary.BigEndian.Uint32(body[:4]))
	rest := body[4:]
	if len(rest) < 2 {
		return 0, nil, fmt.Errorf("missing nonceTPM")
	}
	nlen := int(binary.BigEndian.Uint16(rest[:2]))
	if len(rest) < 2+nlen {
		return 0, nil, fmt.Errorf("truncated nonceTPM")
	}
	return sessionHandle, rest[2 : 2+nlen], nil
}

func rawFlush(rwc interface {
	Send([]byte) ([]byte, error)
}, h tpm2.TPMHandle) {
	const ccFlushContext = 0x00000165
	const stNoSessions = 0x8001
	cmd := buildCommand(stNoSessions, ccFlushContext, be32(uint32(h)), nil, nil)
	rwc.Send(cmd)
}

// --- raw command/response helpers ------------------------------------------

func buildCommand(tag uint16, commandCode uint32, handles, authArea, params []byte) []byte {
	body := concat(handles, authArea, params)
	cmd := concat(be16(tag), be32(uint32(10+len(body))), be32(commandCode), body)
	return cmd
}

func responseBody(rsp []byte) ([]byte, error) {
	if err := checkResponseCode(rsp); err != nil {
		return nil, err
	}
	return rsp[10:], nil
}

func checkResponseCode(rsp []byte) error {
	if len(rsp) < 10 {
		return fmt.Errorf("short TPM response (%d bytes)", len(rsp))
	}
	rc := binary.BigEndian.Uint32(rsp[6:10])
	if rc != 0 {
		return fmt.Errorf("TPM error response 0x%x", rc)
	}
	return nil
}

func be16(v uint16) []byte { b := make([]byte, 2); binary.BigEndian.PutUint16(b, v); return b }
func be32(v uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); return b }

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
