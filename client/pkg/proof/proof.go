package proof

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"
)

type Proof struct {
	data string
}

// The namespace used for signing the proof
const Namespace = "proof-of-possession@com.github.serverless-ssh-ca.andrewheberle"

// getTimestamp is a variable so it can be overridden in tests
var getTimestamp = func() int64 {
	return time.Now().UnixMilli()
}

// Generate creates a proof by signing the current timestamp using SSHSIG
// and the public key fingerprint with the provided signer.
//
// The proof is returned as a string in the format:
// <timestamp>.<fingerprint>.<base64 armored_signature>
func Generate(signer ssh.Signer) (*Proof, error) {
	// generate data to sign
	timestamp := getTimestamp()
	fingerprint := ssh.FingerprintSHA256(signer.PublicKey())
	dataToSign := []string{
		fmt.Sprintf("%d", timestamp),
		fingerprint,
	}

	// sign data and add to end
	data := []byte(strings.Join(dataToSign, "."))
	sig, err := sshsig.Sign(bytes.NewReader(data), signer, sshsig.HashSHA512, Namespace)
	if err != nil {
		return nil, err
	}
	armoredSignature := sshsig.Armor(sig)
	signedData := append(dataToSign, base64.StdEncoding.EncodeToString(armoredSignature))

	// return encoded data
	return &Proof{data: strings.Join(signedData, ".")}, nil
}

// Parse takes a proof string and validates it is in the expected format, returning a Proof struct if valid.
func Parse(proof string) (Proof, error) {
	_, _, _, err := parse(proof)
	if err != nil {
		return Proof{}, fmt.Errorf("invalid proof format: %v", err)
	}

	return Proof{data: proof}, nil
}

func parse(proof string) (timestamp int64, fingerprint string, signature *sshsig.Signature, err error) {
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return 0, "", nil, fmt.Errorf("invalid proof format")
	}

	// we dont verify fingerprint here, just return it
	fingerprint = parts[1]

	// decode timestamp (this does not verify it is within an acceptable range, just that it is a valid integer)
	timestamp, err = strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, "", nil, fmt.Errorf("invalid timestamp in proof: %v", err)
	}

	// check signature format is expected and can be parsed back
	sig, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return 0, "", nil, fmt.Errorf("invalid signature encoding in proof: %v", err)
	}

	// dearmor signature
	signature, err = sshsig.Unarmor(sig)
	if err != nil {
		return 0, "", nil, fmt.Errorf("invalid signature format in proof: %v", err)
	}

	return timestamp, fingerprint, signature, nil
}

// Verify checks the proof is valid by verifying the signature and that the timestamp is within the allowed range.
func (p Proof) Verify(pub ssh.PublicKey, allowedrange time.Duration) error {
	timestamp, fingerprint, signature, err := parse(p.data)
	if err != nil {
		return err
	}

	// verify timestamp is within allowed range (this is to prevent replay attacks, but allows for some clock skew between client and server)
	proofTime := time.UnixMilli(timestamp)
	now := getTimestamp()
	if proofTime.Before(time.UnixMilli(now).Add(-allowedrange)) || proofTime.After(time.UnixMilli(now).Add(allowedrange)) {
		return fmt.Errorf("proof timestamp is outside of allowed time range")
	}

	// verify fingerprint matches signer
	expectedFingerprint := ssh.FingerprintSHA256(pub)
	if fingerprint != expectedFingerprint {
		return fmt.Errorf("proof fingerprint did not match (expected fingerprint %s, got %s)", expectedFingerprint, fingerprint)
	}

	// verify signature
	data := fmt.Appendf(nil, "%d.%s", timestamp, fingerprint)
	if err := sshsig.Verify(bytes.NewReader(data), signature, pub, sshsig.HashSHA512, Namespace); err != nil {
		return fmt.Errorf("signature did not verify: %v", err)
	}

	return nil
}

// Ensure Proof implements fmt.Stringer interface
var _ fmt.Stringer = Proof{}

// String returns the proof data as a string
func (p Proof) String() string {
	return p.data
}

// Ensure Proof implements json.Marshaler interface
var _ json.Marshaler = &Proof{}

// MarshalJSON returns the proof data as a JSON string
func (p Proof) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.data)
}
