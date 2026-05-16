package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/mp-pinheiro/socket-proxy/internal/config"
)

type execRequest struct {
	Privileged bool `json:",omitempty"`
}

// checkSecurityRestrictions inspects container create/update and exec requests
// for dangerous HostConfig fields (privileged, host namespace, capabilities, etc).
func checkSecurityRestrictions(secCfg *config.SecurityConfig, r *http.Request) error {
	if secCfg == nil || !secCfg.Enabled() {
		return nil
	}
	if r.Method != http.MethodPost {
		return nil
	}

	pathParts := strings.Split(r.URL.Path, "/")

	switch {
	case len(pathParts) >= 4 && pathParts[2] == "containers" && pathParts[3] == "create":
		return checkContainerSecurity(secCfg, r)
	case len(pathParts) >= 5 && pathParts[2] == "containers" && pathParts[4] == "update":
		return checkContainerSecurity(secCfg, r)
	case len(pathParts) >= 5 && pathParts[2] == "containers" && pathParts[4] == "exec":
		return checkExecSecurity(secCfg, r)
	case len(pathParts) >= 4 && pathParts[2] == "services" && pathParts[3] == "create":
		return checkServiceSecurity(secCfg, r)
	case len(pathParts) >= 5 && pathParts[2] == "services" && pathParts[4] == "update":
		return checkServiceSecurity(secCfg, r)
	default:
		return nil
	}
}

func checkContainerSecurity(secCfg *config.SecurityConfig, r *http.Request) error {
	body, err := readAndRestoreBody(r)
	if err != nil {
		return err
	}

	var req containerCreateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		slog.Debug("failed to parse container request for security check", "error", err)
		return nil
	}

	return validateHostConfigSecurity(secCfg, req.HostConfig)
}

func checkServiceSecurity(secCfg *config.SecurityConfig, r *http.Request) error {
	body, err := readAndRestoreBody(r)
	if err != nil {
		return err
	}

	var req swarmServiceSpec
	if err := json.Unmarshal(body, &req); err != nil {
		slog.Debug("failed to parse service request for security check", "error", err)
		return nil
	}

	if req.TaskTemplate.ContainerSpec == nil {
		return nil
	}

	return validateHostConfigSecurity(secCfg, &containerHostConfig{})
}

func checkExecSecurity(secCfg *config.SecurityConfig, r *http.Request) error {
	if !secCfg.DenyPrivileged {
		return nil
	}

	body, err := readAndRestoreBody(r)
	if err != nil {
		return err
	}

	var req execRequest
	if err := json.Unmarshal(body, &req); err != nil {
		slog.Debug("failed to parse exec request for security check", "error", err)
		return nil
	}

	if req.Privileged {
		return fmt.Errorf("privileged exec is denied")
	}
	return nil
}

func validateHostConfigSecurity(secCfg *config.SecurityConfig, hc *containerHostConfig) error {
	if hc == nil {
		return nil
	}

	if secCfg.DenyPrivileged && hc.Privileged {
		return fmt.Errorf("privileged containers are denied")
	}

	if secCfg.DenyHostNetwork && hc.NetworkMode == "host" {
		return fmt.Errorf("host network mode is denied")
	}

	if secCfg.DenyHostPID && hc.PidMode == "host" {
		return fmt.Errorf("host PID mode is denied")
	}

	if secCfg.DenyHostIPC && hc.IpcMode == "host" {
		return fmt.Errorf("host IPC mode is denied")
	}

	if secCfg.DenyDevices && len(hc.Devices) > 0 {
		return fmt.Errorf("device mappings are denied")
	}

	if len(hc.CapAdd) > 0 {
		if err := checkCapabilities(secCfg, hc.CapAdd); err != nil {
			return err
		}
	}

	if secCfg.DenySecurityOpt && len(hc.SecurityOpt) > 0 {
		if err := checkSecurityOpts(hc.SecurityOpt); err != nil {
			return err
		}
	}

	return nil
}

func checkCapabilities(secCfg *config.SecurityConfig, capAdd []string) error {
	if len(secCfg.DenyCapabilities) == 1 && strings.ToUpper(secCfg.DenyCapabilities[0]) == "ALL" {
		return fmt.Errorf("adding capabilities is denied (cap: %s)", strings.Join(capAdd, ","))
	}

	for _, cap := range capAdd {
		capUpper := strings.ToUpper(cap)
		for _, denied := range secCfg.DenyCapabilities {
			if strings.ToUpper(denied) == capUpper {
				return fmt.Errorf("capability %s is denied", cap)
			}
		}
	}
	return nil
}

var dangerousSecurityOpts = []string{
	"apparmor=unconfined",
	"seccomp=unconfined",
	"no-new-privileges=false",
	"writable-cgroups=true",
}

func checkSecurityOpts(opts []string) error {
	for _, opt := range opts {
		optLower := strings.ToLower(opt)
		for _, dangerous := range dangerousSecurityOpts {
			if optLower == dangerous {
				return fmt.Errorf("security option %q is denied", opt)
			}
		}
	}
	return nil
}
