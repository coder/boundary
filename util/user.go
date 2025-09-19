package util

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
)

// GetUserInfo returns information about the current user, handling sudo scenarios
func GetUserInfo() (string, int, int, string, string) {
	// Only consider SUDO_USER if we're actually running with elevated privileges
	// In environments like Coder workspaces, SUDO_USER may be set to 'root'
	// but we're not actually running under sudo
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" && os.Geteuid() == 0 && sudoUser != "root" {
		// We're actually running under sudo with a non-root original user
		user, err := user.Lookup(sudoUser)
		if err != nil {
			return getCurrentUserInfo() // Fallback to current user
		}

		uid, _ := strconv.Atoi(os.Getenv("SUDO_UID"))
		gid, _ := strconv.Atoi(os.Getenv("SUDO_GID"))

		// If we couldn't get UID/GID from env, parse from user info
		if uid == 0 {
			if parsedUID, err := strconv.Atoi(user.Uid); err == nil {
				uid = parsedUID
			}
		}
		if gid == 0 {
			if parsedGID, err := strconv.Atoi(user.Gid); err == nil {
				gid = parsedGID
			}
		}

		configDir := getConfigDir(user.HomeDir)

		return sudoUser, uid, gid, user.HomeDir, configDir
	}

	// Not actually running under sudo, use current user
	return getCurrentUserInfo()
}

// getCurrentUserInfo gets information for the current user
func getCurrentUserInfo() (string, int, int, string, string) {
	currentUser, err := user.Current()
	if err != nil {
		// Fallback with empty values if we can't get user info
		return "", 0, 0, "", ""
	}

	uid, _ := strconv.Atoi(currentUser.Uid)
	gid, _ := strconv.Atoi(currentUser.Gid)

	configDir := getConfigDir(currentUser.HomeDir)

	return currentUser.Username, uid, gid, currentUser.HomeDir, configDir
}

// getConfigDir determines the config directory based on XDG_CONFIG_HOME or fallback
func getConfigDir(homeDir string) string {
	// Use XDG_CONFIG_HOME if set, otherwise fallback to ~/.config/coder_boundary
	if xdgConfigHome := os.Getenv("XDG_CONFIG_HOME"); xdgConfigHome != "" {
		return filepath.Join(xdgConfigHome, "coder_boundary")
	}
	return filepath.Join(homeDir, ".config", "coder_boundary")
}
