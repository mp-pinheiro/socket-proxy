package config

import (
	"os"
	"strconv"
	"strings"
)

type SecurityConfig struct {
	DenyPrivileged  bool
	DenyHostNetwork bool
	DenyHostPID     bool
	DenyHostIPC     bool
	DenyDevices     bool
	DenySecurityOpt bool
	ResolveSymlinks bool
	DenyCapabilities []string
}

func (s *SecurityConfig) Enabled() bool {
	return s.DenyPrivileged || s.DenyHostNetwork || s.DenyHostPID ||
		s.DenyHostIPC || s.DenyDevices || s.DenySecurityOpt ||
		len(s.DenyCapabilities) > 0
}

func InitSecurityConfig() *SecurityConfig {
	cfg := &SecurityConfig{
		DenyPrivileged:   envBool("SP_DENY_PRIVILEGED", true),
		DenyHostNetwork:  envBool("SP_DENY_HOST_NETWORK", true),
		DenyHostPID:      envBool("SP_DENY_HOST_PID", true),
		DenyHostIPC:      envBool("SP_DENY_HOST_IPC", true),
		DenyDevices:      envBool("SP_DENY_DEVICES", true),
		DenySecurityOpt:  envBool("SP_DENY_SECURITYOPT", true),
		ResolveSymlinks:  envBool("SP_RESOLVE_SYMLINKS", true),
		DenyCapabilities: envStringSlice("SP_DENY_CAPABILITIES", "ALL"),
	}
	return cfg
}

func envBool(key string, defaultVal bool) bool {
	val, ok := os.LookupEnv(key)
	if !ok {
		return defaultVal
	}
	parsed, err := strconv.ParseBool(val)
	if err != nil {
		return defaultVal
	}
	return parsed
}

func envStringSlice(key string, defaultVal string) []string {
	val, ok := os.LookupEnv(key)
	if !ok {
		val = defaultVal
	}
	if val == "" {
		return nil
	}
	parts := strings.Split(val, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}
