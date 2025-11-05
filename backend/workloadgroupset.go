package api

import (
	"encoding/binary"
	"encoding/hex"

	"github.com/spaolacci/murmur3"
)

// WorkloadGroupSetLabelFromSelector returns the stable label for the given app selector.
// If the selector is nil or invalid, an empty string is returned.
func WorkloadGroupSetLabelFromSelector(selector *AppSelector) string {

	// currently we only have Kubernetes selectors
	if selector == nil || selector.Type != AppSelectorTypeKubernetes {
		return ""
	}

	return WorkloadGroupSetLabelFromKubernetesSelector(selector.Kubernetes)
}

// WorkloadGroupSetHashFromSelector returns a stable hash for the given workload group set selector.
// If the selector is nil or invalid, an empty string is returned. The hash is generated from the label.
func WorkloadGroupSetHashFromSelector(selector *AppSelector) string {

	// currently we only have Kubernetes selectors
	if selector == nil || selector.Type != AppSelectorTypeKubernetes {
		return ""
	}

	return WorkloadGroupSetHashFromKubernetesSelector(selector.Kubernetes)
}

// WorkloadGroupSetLabelFromKubernetesSelector returns the stabel label for the given Kubernetes workload selector.
// If the selector is nil or invalid, an empty string is returned.
func WorkloadGroupSetLabelFromKubernetesSelector(selector *KubernetesWorkloadGroupSetSelector) string {

	if selector == nil {
		return ""
	}

	return "k8s:namespace=" + selector.KubernetesNamespace
}

// WorkloadGroupSetHashFromKubernetesSelector returns a stable hash for the given Kubernetes workload selector.
// If the selector is nil or invalid, an empty string is returned. The hash is generated from the label.
func WorkloadGroupSetHashFromKubernetesSelector(selector *KubernetesWorkloadGroupSetSelector) string {

	if selector == nil {
		return ""
	}

	label := WorkloadGroupSetLabelFromKubernetesSelector(selector)
	if label == "" {
		return ""
	}

	h1, h2 := murmur3.Sum128([]byte(label))
	var b [16]byte
	binary.BigEndian.PutUint64(b[0:8], h1)
	binary.BigEndian.PutUint64(b[8:16], h2)
	return "wgs-" + hex.EncodeToString(b[:])
}
