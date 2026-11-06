//go:build windows

package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"time"

	"fyne.io/systray"
	"golang.org/x/sys/windows"

	"github.com/nguyenthanh1205tb/snisplit/internal/logo"
)

// cmdTray shows a notification-area icon to start/stop the proxy, toggle
// "start at login", open the log and install updates.
func cmdTray(args []string) error {
	fset := flag.NewFlagSet("tray", flag.ExitOnError)
	foreground := fset.Bool("foreground", false, "stay attached to the terminal")
	startProxy := fset.Bool("start", false, "start the proxy if it is not running (used at login)")
	fset.Parse(args)

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if !*foreground && os.Getenv("SNISPLIT_TRAY_CHILD") == "" {
		// Relaunch without a console window and return to the prompt.
		cmd := exec.Command(exe, "tray")
		cmd.Env = append(os.Environ(), "SNISPLIT_TRAY_CHILD=1")
		if *startProxy {
			cmd.Env = append(cmd.Env, "SNISPLIT_TRAY_START=1")
		}
		cmd.SysProcAttr = detachAttr()
		if err := cmd.Start(); err != nil {
			return err
		}
		cmd.Process.Release()
		fmt.Println("tray icon started")
		return nil
	}
	if !trayMutex() {
		fmt.Println("tray icon is already running")
		return nil
	}
	t := &tray{exe: exe, start: *startProxy || os.Getenv("SNISPLIT_TRAY_START") == "1"}
	systray.Run(t.ready, t.exit)
	return nil
}

// trayMutex makes sure only one tray icon runs per user session. It waits a
// little so a tray that is restarting after an update can take over.
func trayMutex() bool {
	name, _ := windows.UTF16PtrFromString(`Local\snisplit-tray`)
	for i := 0; i < 20; i++ {
		h, err := windows.CreateMutex(nil, false, name)
		if err == nil {
			return true // keep the handle open for the life of the process
		}
		if h != 0 {
			windows.CloseHandle(h)
		}
		if err != windows.ERROR_ALREADY_EXISTS {
			return true
		}
		time.Sleep(250 * time.Millisecond)
	}
	return false
}

type tray struct {
	exe      string // path captured at start; still valid after an update renames the old file
	start    bool
	relaunch bool
}

// run executes snisplit with args without showing a console window.
func (t *tray) run(args ...string) error {
	cmd := exec.Command(t.exe, args...)
	cmd.SysProcAttr = detachAttr()
	return cmd.Run()
}

// autostartValue returns the login entry ("" when there is none).
func autostartValue() string {
	cmd := exec.Command("reg", "query", runKey, "/v", "snisplit")
	cmd.SysProcAttr = detachAttr()
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return regValue(string(out))
}

func autostartEnabled() bool { return autostartValue() != "" }

func (t *tray) ready() {
	// tray sizes only, all with the larger "compact" mark that stays readable at 16 px
	trayIcon := func(st logo.State) []byte { return logo.ICO(st, 64, 16, 20, 24, 32, 40, 48, 64) }
	iconOn, iconOff, iconWarn := trayIcon(logo.Running), trayIcon(logo.Stopped), trayIcon(logo.Failing)
	systray.SetIcon(iconOff)
	systray.SetTooltip("snisplit")

	mState := systray.AddMenuItem("snisplit", "")
	mState.Disable()
	mTraffic := systray.AddMenuItem("", "")
	mTraffic.Disable()
	systray.AddSeparator()
	mStart := systray.AddMenuItem("Start proxy", "Start the proxy in the background")
	mStop := systray.AddMenuItem("Stop proxy", "Stop the proxy")
	mRestart := systray.AddMenuItem("Restart proxy", "Stop and start the proxy")
	systray.AddSeparator()
	if legacyAutostart(autostartValue()) { // pre-0.4 entry: start this icon at login too
		t.run("autostart", "on")
	}
	mLogin := systray.AddMenuItemCheckbox("Start at login", "Start the proxy and this icon when you log in", autostartEnabled())
	mLog := systray.AddMenuItem("Open log", "Open the proxy log file")
	mUpdate := systray.AddMenuItem("Check for updates", "")
	systray.AddSeparator()
	mQuit := systray.AddMenuItem("Quit icon (proxy keeps running)", "")

	var lastFailures int64 = -1
	refresh := func() {
		s, err := getStatus(defaultPort)
		if err != nil {
			systray.SetIcon(iconOff)
			systray.SetTooltip("snisplit: stopped")
			mState.SetTitle("Proxy stopped")
			mTraffic.Hide()
			mStart.Enable()
			mStop.Disable()
			mRestart.Disable()
			return
		}
		icon := iconOn
		if lastFailures >= 0 && s.Failures > lastFailures { // new failures since the last poll
			icon = iconWarn
		}
		lastFailures = s.Failures
		systray.SetIcon(icon)
		systray.SetTooltip(fmt.Sprintf("snisplit %s: running\n%s, %d failed", s.Version, plural(s.Connections, "connection"), s.Failures))
		mState.SetTitle(fmt.Sprintf("Running %s (up %s)", s.Version, s.Uptime))
		mTraffic.SetTitle(fmt.Sprintf("%s, %d failed, %s", plural(s.Connections, "connection"), s.Failures, plural(int64(s.Restarts), "restart")))
		mTraffic.Show()
		mStart.Disable()
		mStop.Enable()
		mRestart.Enable()
	}

	if t.start {
		if _, err := getStatus(defaultPort); err != nil {
			t.run("start")
		}
	}
	refresh()

	go func() {
		tick := time.NewTicker(3 * time.Second)
		defer tick.Stop()
		var updateTag string
		for {
			select {
			case <-tick.C:
				refresh()
			case <-mStart.ClickedCh:
				t.run("start")
				refresh()
			case <-mStop.ClickedCh:
				t.run("stop")
				refresh()
			case <-mRestart.ClickedCh:
				t.run("stop")
				t.run("start")
				refresh()
			case <-mLogin.ClickedCh:
				if mLogin.Checked() {
					t.run("autostart", "off")
				} else {
					t.run("autostart", "on")
				}
				if autostartEnabled() {
					mLogin.Check()
				} else {
					mLogin.Uncheck()
				}
			case <-mLog.ClickedCh:
				open := exec.Command("rundll32", "url.dll,FileProtocolHandler", logPath())
				open.Start()
			case <-mUpdate.ClickedCh:
				if updateTag != "" {
					mUpdate.SetTitle("Updating...")
					mUpdate.Disable()
					if err := t.run("update"); err == nil {
						t.relaunch = true
						systray.Quit()
						return
					}
					mUpdate.SetTitle("Update failed - see log")
					mUpdate.Enable()
					continue
				}
				tag, err := latestTag(githubSource)
				switch {
				case err != nil:
					mUpdate.SetTitle("Update check failed - click to retry")
				case tag == version:
					mUpdate.SetTitle("Up to date (" + version + ")")
				case packageManager(t.exe) != "":
					mUpdate.SetTitle("Update to " + tag + " with " + packageManager(t.exe))
				default:
					updateTag = tag
					mUpdate.SetTitle("Install update " + tag)
				}
			case <-mQuit.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()
}

func (t *tray) exit() {
	if !t.relaunch {
		return
	}
	cmd := exec.Command(t.exe, "tray") // the updated binary
	cmd.Env = append(os.Environ(), "SNISPLIT_TRAY_CHILD=1")
	cmd.SysProcAttr = detachAttr()
	cmd.Start()
}
