package api

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/spaolacci/murmur3"
)

// WorkloadGroupLabelFromSelector returns the stable label for the given workload selector.
// If the selector is nil or invalid, an empty string is returned.
func WorkloadGroupLabelFromSelector(selector *AppComponentSelector) string {

	// currently we only have Kubernetes selectors
	if selector == nil || selector.Type != AppComponentSelectorTypeKubernetes {
		return ""
	}

	return WorkloadGroupLabelFromKubernetesSelector(selector.Kubernetes)
}

// WorkloadGroupHashFromSelector returns a stable hash for the given workload selector.
// If the selector is nil or invalid, an empty string is returned. The hash is generated from the label.
func WorkloadGroupHashFromSelector(selector *AppComponentSelector) string {

	// currently we only have Kubernetes selectors
	if selector == nil || selector.Type != AppComponentSelectorTypeKubernetes {
		return ""
	}

	return WorkloadGroupHashFromKubernetesSelector(selector.Kubernetes)
}

// WorkloadGroupLabelFromKubernetesSelector returns the stabel label for the given Kubernetes workload selector.
// If the selector is nil or invalid, an empty string is returned.
func WorkloadGroupLabelFromKubernetesSelector(selector *KubernetesWorkloadGroupSelector) string {

	if selector == nil {
		return ""
	}

	switch selector.Type {
	case KubernetesWorkloadGroupSelectorTypePod:
		return fmt.Sprintf("k8s:pod=%s,namespace=%s", selector.Name, selector.KubernetesNamespace)
	case KubernetesWorkloadGroupSelectorTypeDeployment:
		return fmt.Sprintf("k8s:deployment=%s,namespace=%s", selector.Name, selector.KubernetesNamespace)
	case KubernetesWorkloadGroupSelectorTypeStatefulSet:
		return fmt.Sprintf("k8s:statefulset=%s,namespace=%s", selector.Name, selector.KubernetesNamespace)
	case KubernetesWorkloadGroupSelectorTypeJob:
		return fmt.Sprintf("k8s:job=%s,namespace=%s", selector.Name, selector.KubernetesNamespace)
	case KubernetesWorkloadGroupSelectorTypeCronJob:
		return fmt.Sprintf("k8s:cronjob=%s,namespace=%s", selector.Name, selector.KubernetesNamespace)
	default:
		return ""
	}
}

// WorkloadGroupHashFromKubernetesSelector returns a stable hash for the given Kubernetes workload selector.
// If the selector is nil or invalid, an empty string is returned. The hash is generated from the label.
func WorkloadGroupHashFromKubernetesSelector(selector *KubernetesWorkloadGroupSelector) string {

	if selector == nil {
		return ""
	}

	label := WorkloadGroupLabelFromKubernetesSelector(selector)
	if label == "" {
		return ""
	}

	h1, h2 := murmur3.Sum128([]byte(label))
	var b [16]byte
	binary.BigEndian.PutUint64(b[0:8], h1)
	binary.BigEndian.PutUint64(b[8:16], h2)
	return "wg-" + hex.EncodeToString(b[:])
}
