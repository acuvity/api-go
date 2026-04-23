package api

import (
	"encoding/binary"
	"encoding/hex"

	"github.com/spaolacci/murmur3"
)

// WorkloadGroupHashFromLabel returns the "wg-<hex>" hash for the given workload group label.
func WorkloadGroupHashFromLabel(label string) string {
	return "wg-" + workloadLabelStringToHash(label)
}

// WorkloadGroupSetHashFromLabel returns the "wgs-<hex>" hash for the given workload group set label.
func WorkloadGroupSetHashFromLabel(label string) string {
	return "wgs-" + workloadLabelStringToHash(label)
}

// workloadLabelStringToHash returns the murmur3 hex hash of the given string.
func workloadLabelStringToHash(s string) string {
	h1, h2 := murmur3.Sum128([]byte(s))
	var b [16]byte
	binary.BigEndian.PutUint64(b[0:8], h1)
	binary.BigEndian.PutUint64(b[8:16], h2)
	return hex.EncodeToString(b[:])
}
