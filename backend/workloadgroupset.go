package api

// WorkloadGroupSetLabelFromSelector returns the stable label for the given app selector.
// If the selector is nil or invalid, an empty string is returned.
// The appName parameter is used for None type selectors where the label is derived from the app name.
func WorkloadGroupSetLabelFromSelector(selector *AppSelector, appName string) string {

	if selector == nil {
		return ""
	}

	switch selector.Type {
	case AppSelectorTypeKubernetes:
		return WorkloadGroupSetLabelFromKubernetesSelector(selector.Kubernetes)
	case AppSelectorTypeNone:
		if appName == "" {
			return ""
		}
		return "none:app=" + appName
	default:
		return ""
	}
}

// WorkloadGroupSetHashFromSelector returns a stable hash for the given workload group set selector.
// If the selector is nil or invalid, an empty string is returned. The hash is generated from the label.
// The appName parameter is used for None type selectors where the label is derived from the app name.
func WorkloadGroupSetHashFromSelector(selector *AppSelector, appName string) string {

	label := WorkloadGroupSetLabelFromSelector(selector, appName)
	if label == "" {
		return ""
	}

	return WorkloadGroupSetHashFromLabel(label)
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

	return WorkloadGroupSetHashFromLabel(label)
}
