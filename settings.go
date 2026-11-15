package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// settings are the choices made with "snisplit upstream" and "snisplit
// browser", so the proxy keeps them however it is started (tray, login, start).
type settings struct {
	Upstream string `json:"upstream,omitempty"`
	Browser  bool   `json:"browser,omitempty"`
	PrevPAC  string `json:"prev_pac,omitempty"` // system PAC URL before browser mode, restored by "browser off"
}

var settingsPath = func() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = filepath.Dir(logPath())
	}
	return filepath.Join(dir, "snisplit", "settings.json")
}

func loadSettings() settings {
	var s settings
	if b, err := os.ReadFile(settingsPath()); err == nil {
		json.Unmarshal(b, &s)
	}
	return s
}

func saveSettings(s settings) error {
	p := settingsPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	return os.WriteFile(p, b, 0o600) // may hold a proxy password
}
