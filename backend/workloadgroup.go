package api

import (
	"fmt"
)

// WorkloadGroupLabelFromSelector returns the stable label for the given workload selector.
// If the selector is nil or invalid, an empty string is returned.
// The appName and componentName parameters are used for None type selectors where the label is derived from names.
func WorkloadGroupLabelFromSelector(selector *AppComponentSelector, appName string, componentName string) string {

	if selector == nil {
		return ""
	}

	switch selector.Type {
	case AppComponentSelectorTypeKubernetes:
		return WorkloadGroupLabelFromKubernetesSelector(selector.Kubernetes)
	case AppComponentSelectorTypeNone:
		if appName == "" || componentName == "" {
			return ""
		}
		return fmt.Sprintf("none:app=%s,component=%s", appName, componentName)
	default:
		return ""
	}
}

// WorkloadGroupHashFromSelector returns a stable hash for the given workload selector.
// If the selector is nil or invalid, an empty string is returned. The hash is generated from the label.
// The appName and componentName parameters are used for None type selectors where the label is derived from names.
func WorkloadGroupHashFromSelector(selector *AppComponentSelector, appName string, componentName string) string {

	label := WorkloadGroupLabelFromSelector(selector, appName, componentName)
	if label == "" {
		return ""
	}

	return WorkloadGroupHashFromLabel(label)
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
	case KubernetesWorkloadGroupSelectorTypeDaemonSet:
		return fmt.Sprintf("k8s:daemonset=%s,namespace=%s", selector.Name, selector.KubernetesNamespace)
	case KubernetesWorkloadGroupSelectorTypeCustom:
		return customLabel(selector.Custom, selector.Name, selector.KubernetesNamespace)
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

	return WorkloadGroupHashFromLabel(label)
}

func formatCustom(custom *KubernetesWorkloadGroupSelectorCustomType) string {
	if custom.Group == "" {
		return fmt.Sprintf("core[%s]", custom.Kind)
	}
	return fmt.Sprintf("%s[%s]", custom.Group, custom.Kind)
}

func customLabel(custom *KubernetesWorkloadGroupSelectorCustomType, name, namespace string) string {

	if custom == nil {
		return ""
	}

	customStr := formatCustom(custom)

	if namespace == "" {
		return fmt.Sprintf("k8s:%s=%s", customStr, name)
	}

	return fmt.Sprintf("k8s:%s=%s,namespace=%s", customStr, name, namespace)
}
