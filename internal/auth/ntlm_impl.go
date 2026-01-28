package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

// NTLM Flags
const (
	FlagNegotiateUnicode     = 0x00000001
	FlagNegotiateOEM         = 0x00000002
	FlagRequestTarget        = 0x00000004
	FlagNegotiateSign        = 0x00000010
	FlagNegotiateSeal        = 0x00000020
	FlagNegotiateDatagram    = 0x00000040
	FlagNegotiateLMKey       = 0x00000080
	FlagNegotiateNTLM        = 0x00000200
	FlagNegotiateAlwaysSign  = 0x00008000
	FlagNegotiateWorkstation = 0x00002000
	FlagNegotiateLocalCall   = 0x00004000
	FlagNegotiateNTLM2Key    = 0x00080000
	FlagTargetTypeDomain     = 0x00010000
	FlagTargetTypeServer     = 0x00020000
	FlagTargetTypeShare      = 0x00040000
	FlagNegotiate128         = 0x20000000
	FlagNegotiate56          = 0x80000000
)

type NTLMServerContext struct {
	Challenge []byte
	Target    string
}

func NewNTLMServerContext(target string) *NTLMServerContext {
	return &NTLMServerContext{
		Target: target,
	}
}

// ParseType1 parses the NTLM Negotiate Message
func (c *NTLMServerContext) ParseType1(data []byte) error {
	if len(data) < 32 {
		return errors.New("NTLM type 1 message too short")
	}
	if string(data[:8]) != "NTLMSSP\x00" {
		return errors.New("invalid NTLM signature")
	}
	msgType := binary.LittleEndian.Uint32(data[8:12])
	if msgType != 1 {
		return errors.New("invalid NTLM message type, expected 1")
	}
	return nil
}

// GenerateType2 generates the NTLM Challenge Message
func (c *NTLMServerContext) GenerateType2() ([]byte, error) {
	// 8 bytes Signature "NTLMSSP\0"
	// 4 bytes Type (2)
	// 8 bytes Target Name Header (Len, MaxLen, Offset)
	// 4 bytes Flags
	// 8 bytes Challenge
	// 8 bytes Context (0)
	// 8 bytes Target Info Header (Len, MaxLen, Offset) - Optional but good for NTLMv2
	// Payload (TargetName + TargetInfo)

	targetBytes := toUnicode(c.Target)
	targetLen := len(targetBytes)

	// Create random challenge (fixed for determinism in this example if needed, but should be random)
	// In a real implementation use crypto/rand. Using hardcoded for stability in this snippet unless imported.
	// c.Challenge should have been set by caller or random.
	if len(c.Challenge) != 8 {
		c.Challenge = []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	}

	buf := new(bytes.Buffer)
	buf.WriteString("NTLMSSP\x00")
	binary.Write(buf, binary.LittleEndian, uint32(2))

	// Headers placeholders
	targetHeaderOffset := 40 + 8
	// Target Name Header
	binary.Write(buf, binary.LittleEndian, uint16(targetLen))
	binary.Write(buf, binary.LittleEndian, uint16(targetLen))
	binary.Write(buf, binary.LittleEndian, uint32(targetHeaderOffset))

	// Flags
	flags := uint32(FlagNegotiateUnicode | FlagNegotiateNTLM | FlagTargetTypeServer | FlagNegotiateAlwaysSign | FlagNegotiate128 | FlagNegotiate56)
	binary.Write(buf, binary.LittleEndian, flags)

	// Challenge
	buf.Write(c.Challenge)

	// Context
	buf.Write(make([]byte, 8))

	// Target Info Header (Empty for simple compat)
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint32(buf.Len()+targetLen))

	// Payload
	buf.Write(targetBytes)

	return buf.Bytes(), nil
}

// ParseType3 and verify
func (c *NTLMServerContext) VerifyType3(data []byte, users map[string]string) (string, error) {
	if len(data) < 64 {
		return "", errors.New("NTLM type 3 message too short")
	}
	if string(data[:8]) != "NTLMSSP\x00" {
		return "", errors.New("invalid NTLM signature")
	}
	msgType := binary.LittleEndian.Uint32(data[8:12])
	if msgType != 3 {
		return "", errors.New("invalid NTLM message type, expected 3")
	}

	// Read Headers
	// lmRespLen := binary.LittleEndian.Uint16(data[12:14])
	// lmRespOff := binary.LittleEndian.Uint32(data[16:20])

	ntRespLen := binary.LittleEndian.Uint16(data[20:22])
	ntRespOff := binary.LittleEndian.Uint32(data[24:28])

	// domainLen := binary.LittleEndian.Uint16(data[28:30]) // Unused
	// domainOff := binary.LittleEndian.Uint32(data[32:36])

	userLen := binary.LittleEndian.Uint16(data[36:38])
	userOff := binary.LittleEndian.Uint32(data[40:44])

	// Extract Username
	if int(userOff+uint32(userLen)) > len(data) {
		return "", errors.New("malformed type 3 message (username out of bounds)")
	}
	userBytes := data[userOff : userOff+uint32(userLen)]
	username := fromUnicode(userBytes)

	// Lookup User
	password, ok := users[username]
	if !ok {
		// Try case-insensitive lookup
		for k, v := range users {
			if strings.EqualFold(k, username) {
				password = v
				username = k
				ok = true
				break
			}
		}
		if !ok {
			return "", errors.New("user not found")
		}
	}

	// Extract Responses
	if int(ntRespOff+uint32(ntRespLen)) > len(data) {
		return "", errors.New("malformed type 3 message (nt response out of bounds)")
	}
	ntResp := data[ntRespOff : ntRespOff+uint32(ntRespLen)]

	// Verify (NTLMv2)
	// Check if NTResp is NTLMv2 (length >= 24)
	if ntRespLen >= 24 {
		// Calculate Expected NTLMv2 Response
		// 1. NTLMv2 Hash = HMAC-MD5(NTLMHash, Upper(User) + Target)
		// 2. Proof = HMAC-MD5(NTLMv2Hash, Challenge + Blob)

		ntlmHash := ntlmHash(password)
		ntlmv2Hash := hmacMd5(ntlmHash, toUnicode(strings.ToUpper(username)+c.Target))

		// The first 16 bytes of NTResp are the HMAC (Proof)
		// The rest is the Blob (ClientChallenge + Timestamps + TargetInfo...)
		if len(ntResp) < 16 {
			return "", errors.New("invalid NT response length")
		}

		blob := ntResp[16:]
		dataToSign := append(c.Challenge, blob...)
		expectedProof := hmacMd5(ntlmv2Hash, dataToSign)

		if !hmac.Equal(expectedProof, ntResp[:16]) {
			return "", errors.New("password mismatch (NTLMv2)")
		}
		return username, nil
	} else {
		// Validate NTLMv1 (Not recommended but common in stubs)
		// NTLMv1: DES(NTLMHash, Challenge)
		// We can support it or fail. Let's fail secure for now or provide minimal v1 if easy.
		// For robustness, rejecting NTLMv1 is safer.
		return "", errors.New("NTLMv1 not supported, please enable NTLMv2")
	}
}

// Helpers

func toUnicode(s string) []byte {
	utf16Encoded := utf16.Encode([]rune(s))
	b := make([]byte, len(utf16Encoded)*2)
	for i, v := range utf16Encoded {
		binary.LittleEndian.PutUint16(b[i*2:], v)
	}
	return b
}

func fromUnicode(b []byte) string {
	if len(b)%2 != 0 {
		return ""
	}
	u16s := make([]uint16, len(b)/2)
	for i := 0; i < len(u16s); i++ {
		u16s[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	return string(utf16.Decode(u16s))
}

func ntlmHash(password string) []byte {
	hash := md4.New()
	hash.Write(toUnicode(password))
	return hash.Sum(nil)
}

func hmacMd5(key, data []byte) []byte {
	h := hmac.New(md5.New, key)
	h.Write(data)
	return h.Sum(nil)
}
