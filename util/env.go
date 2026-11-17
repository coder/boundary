package util

import "strings"

// RemoveEnvs returns a copy of base without entries matching keys.
func RemoveEnvs(base []string, keys ...string) []string {
	if len(keys) == 0 {
		return append([]string(nil), base...)
	}

	remove := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		remove[key] = struct{}{}
	}

	filtered := make([]string, 0, len(base))
	for _, env := range base {
		key, _, ok := strings.Cut(env, "=")
		if !ok {
			filtered = append(filtered, env)
			continue
		}
		if _, ok := remove[key]; ok {
			continue
		}
		filtered = append(filtered, env)
	}

	return filtered
}

func MergeEnvs(base []string, extra map[string]string) []string {
	envMap := make(map[string]string)
	for _, env := range base {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}

	for key, value := range extra {
		envMap[key] = value
	}

	merged := make([]string, 0, len(envMap))
	for key, value := range envMap {
		merged = append(merged, key+"="+value)
	}

	return merged
}
