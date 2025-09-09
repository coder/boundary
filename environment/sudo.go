package environment

import (
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

// RestoreOriginalUserEnvironment detects if running under sudo and restores
// the original user's environment variables that are important for subprocess execution.
func RestoreOriginalUserEnvironment(logger *slog.Logger) map[string]string {
	restoredEnv := make(map[string]string)

	// Check if running under sudo by looking for SUDO_USER
	sudoUser := os.Getenv("SUDO_USER")
	if sudoUser == "" {
		logger.Debug("Not running under sudo, no environment restoration needed")
		return restoredEnv
	}

	logger.Debug("Detected sudo execution, restoring original user environment", "sudo_user", sudoUser)

	// Get original user information
	originalUser, err := user.Lookup(sudoUser)
	if err != nil {
		logger.Warn("Failed to lookup original user, skipping environment restoration", "sudo_user", sudoUser, "error", err)
		return restoredEnv
	}

	// Restore basic user identity variables
	restoredEnv["USER"] = sudoUser
	restoredEnv["LOGNAME"] = sudoUser
	restoredEnv["HOME"] = originalUser.HomeDir

	// Restore original user's UID and GID if available
	if sudoUID := os.Getenv("SUDO_UID"); sudoUID != "" {
		restoredEnv["UID"] = sudoUID
	}
	if sudoGID := os.Getenv("SUDO_GID"); sudoGID != "" {
		restoredEnv["GID"] = sudoGID
	}

	// Try to restore a reasonable PATH for the original user
	// This is a best-effort attempt since the original PATH might be complex
	restoredPath := restoreUserPath(originalUser, logger)
	if restoredPath != "" {
		restoredEnv["PATH"] = restoredPath
	}

	// Restore XDG directories for the original user
	restoreXDGEnvironment(originalUser, restoredEnv)

	// Log what we're restoring
	logger.Debug("Restored environment variables for original user", 
		"user", sudoUser, 
		"home", originalUser.HomeDir,
		"restored_vars", len(restoredEnv))

	return restoredEnv
}

// restoreUserPath attempts to construct a reasonable PATH for the original user
func restoreUserPath(originalUser *user.User, logger *slog.Logger) string {
	// Start with comprehensive system paths (in order of preference)
	systemPaths := []string{
		"/usr/local/bin",
		"/usr/bin",
		"/bin",
		"/usr/local/sbin",
		"/usr/sbin",
		"/sbin",
	}

	// Add user-specific paths
	userPaths := []string{
		filepath.Join(originalUser.HomeDir, ".local", "bin"),
		filepath.Join(originalUser.HomeDir, "bin"),
		filepath.Join(originalUser.HomeDir, ".cargo", "bin"),     // Rust tools
		filepath.Join(originalUser.HomeDir, "go", "bin"),         // Go tools
		filepath.Join(originalUser.HomeDir, ".npm-global", "bin"), // npm global tools
	}

	// Check if user paths exist and add them
	var validUserPaths []string
	for _, path := range userPaths {
		if _, err := os.Stat(path); err == nil {
			validUserPaths = append(validUserPaths, path)
			logger.Debug("Found user path", "path", path)
		}
	}

	// Try to preserve paths from current PATH that might be user-specific or important
	var preservedPaths []string
	currentPath := os.Getenv("PATH")
	if currentPath != "" {
		for _, path := range strings.Split(currentPath, ":") {
			// Include paths that contain the user's home directory
			if strings.Contains(path, originalUser.HomeDir) {
				if _, err := os.Stat(path); err == nil {
					preservedPaths = append(preservedPaths, path)
					logger.Debug("Preserved user-specific path from current PATH", "path", path)
				}
			}
			// Also preserve common tool paths that might not be in system paths
			if strings.Contains(path, "/opt/") || strings.Contains(path, "/snap/bin") {
				if _, err := os.Stat(path); err == nil {
					preservedPaths = append(preservedPaths, path)
					logger.Debug("Preserved tool path from current PATH", "path", path)
				}
			}
		}
	}

	// Combine all paths: preserved user paths + valid user paths + system paths
	allPaths := append(preservedPaths, validUserPaths...)
	allPaths = append(allPaths, systemPaths...)

	// Remove duplicates while preserving order
	seen := make(map[string]bool)
	var uniquePaths []string
	for _, path := range allPaths {
		if !seen[path] {
			seen[path] = true
			uniquePaths = append(uniquePaths, path)
		}
	}

	restoredPath := strings.Join(uniquePaths, ":")
	logger.Debug("Restored PATH for user", "user", originalUser.Username, "path", restoredPath)
	return restoredPath
}

// restoreXDGEnvironment restores XDG Base Directory variables for the original user
func restoreXDGEnvironment(originalUser *user.User, restoredEnv map[string]string) {
	homeDir := originalUser.HomeDir

	// Set XDG directories according to the specification
	// https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html
	restoredEnv["XDG_DATA_HOME"] = filepath.Join(homeDir, ".local", "share")
	restoredEnv["XDG_CONFIG_HOME"] = filepath.Join(homeDir, ".config")
	restoredEnv["XDG_STATE_HOME"] = filepath.Join(homeDir, ".local", "state")
	restoredEnv["XDG_CACHE_HOME"] = filepath.Join(homeDir, ".cache")

	// XDG_RUNTIME_DIR is typically /run/user/{uid} but we'll leave it as-is
	// since it requires the actual UID and proper permissions
}

// GetEffectiveUID returns the effective UID that should be used for the subprocess
// This helps determine if we need to drop privileges when running under sudo
func GetEffectiveUID() (int, error) {
	if sudoUID := os.Getenv("SUDO_UID"); sudoUID != "" {
		uid, err := strconv.Atoi(sudoUID)
		if err != nil {
			return 0, fmt.Errorf("invalid SUDO_UID: %v", err)
		}
		return uid, nil
	}
	return os.Getuid(), nil
}

// GetEffectiveGID returns the effective GID that should be used for the subprocess
func GetEffectiveGID() (int, error) {
	if sudoGID := os.Getenv("SUDO_GID"); sudoGID != "" {
		gid, err := strconv.Atoi(sudoGID)
		if err != nil {
			return 0, fmt.Errorf("invalid SUDO_GID: %v", err)
		}
		return gid, nil
	}
	return os.Getgid(), nil
}
