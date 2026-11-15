//go:build windows

package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"fyne.io/systray"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

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

// autostartValue returns the login entry ("" when there is none). It reads
// the registry directly (no reg.exe), so the tray can check it often.
func autostartValue() string {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue("snisplit")
	if err != nil {
		return ""
	}
	return v
}

// autostartDisabled reports whether the login entry was turned off in Task
// Manager's Startup apps page (the entry stays, but Windows skips it).
func autostartDisabled() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	data, _, err := k.GetBinaryValue("snisplit")
	if err != nil {
		return false
	}
	return startupDisabled(data)
}

// autostartEnabled reports whether snisplit really starts at login.
func autostartEnabled() bool { return autostartValue() != "" && !autostartDisabled() }

// runElevated starts exe with args through UAC ("Run as administrator").
func runElevated(exe, args string) error {
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	params, _ := windows.UTF16PtrFromString(args)
	return windows.ShellExecute(0, verb, file, params, nil, windows.SW_HIDE)
}

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
	mBrowser := systray.AddMenuItemCheckbox("Browser mode (all sites)",
		"Send every site in your browsers through snisplit; blocked ones are found and split automatically", loadSettings().Browser)
	mAds := systray.AddMenuItemCheckbox("Block ads", "Refuse ad, tracker and malware domains (needs browser mode)", loadSettings().Adblock)
	mLog := systray.AddMenuItem("Open log", "Open the proxy log file")
	mDoctor := systray.AddMenuItem("Run diagnostics", "Open a window with the results of 'snisplit doctor'")
	mList := systray.AddMenuItem("Update site list", "Download the newest site list (asks for administrator rights)")
	mList.Hide()
	mUpdate := systray.AddMenuItem("Check for updates", "")
	systray.AddSeparator()
	mQuit := systray.AddMenuItem("Quit icon (proxy keeps running)", "")

	var lastFailures int64 = -1
	lastHealth := ""
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
		state := fmt.Sprintf("Running %s (up %s)", s.Version, s.Uptime)
		switch s.Health.State {
		case "blocked":
			icon, state = iconWarn, "Blocked: no method gets through - run diagnostics"
		case "upstream":
			state = "Running through the upstream proxy"
		}
		if s.Health.State != lastHealth { // tell the user when things get worse or recover
			switch {
			case s.Health.State == "blocked":
				notify("snisplit cannot get through", "Your ISP seems to have changed how it blocks. Open the snisplit icon and run diagnostics.")
			case s.Health.State == "upstream":
				notify("snisplit", "Every split method is blocked; using your upstream proxy for blocked sites.")
			case lastHealth == "blocked" || lastHealth == "upstream":
				notify("snisplit", "Getting through again ("+s.Health.Mode+").")
			}
			lastHealth = s.Health.State
		}
		systray.SetIcon(icon)
		systray.SetTooltip(fmt.Sprintf("snisplit %s: %s\n%s, %d failed", s.Version, s.Health.State, plural(s.Connections, "connection"), s.Failures))
		mState.SetTitle(state)
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

	// Offer a site-list update when the list on GitHub has changed.
	checkList := func() {
		cur, _ := os.ReadFile(hostsPath())
		if len(installedNames(string(cur))) == 0 {
			mList.Hide()
			return
		}
		list, err := fetchList("steam")
		if err != nil {
			return
		}
		if added, removed := listDiff(list, string(cur)); len(added)+len(removed) > 0 {
			mList.SetTitle(fmt.Sprintf("Update site list (+%d, -%d)", len(added), len(removed)))
			mList.Show()
		} else {
			mList.Hide()
		}
	}
	go func() {
		time.Sleep(10 * time.Second)
		checkList()
		for range time.Tick(24 * time.Hour) {
			checkList()
		}
	}()

	go func() {
		tick := time.NewTicker(3 * time.Second)
		defer tick.Stop()
		var updateTag string
		for {
			select {
			case <-tick.C:
				refresh()
				if on := autostartEnabled(); on != mLogin.Checked() { // changed in Task Manager
					if on {
						mLogin.Check()
					} else {
						mLogin.Uncheck()
					}
				}
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
			case <-mBrowser.ClickedCh:
				if mBrowser.Checked() {
					t.run("browser", "off")
				} else {
					t.run("browser", "on")
				}
				if loadSettings().Browser {
					mBrowser.Check()
				} else {
					mBrowser.Uncheck()
				}
			case <-mAds.ClickedCh:
				if mAds.Checked() {
					t.run("adblock", "off")
				} else {
					t.run("adblock", "on")
					if !loadSettings().Browser { // ad blocking needs browser mode
						t.run("browser", "on")
						mBrowser.Check()
					}
				}
				if loadSettings().Adblock {
					mAds.Check()
				} else {
					mAds.Uncheck()
				}
			case <-mLog.ClickedCh:
				open := exec.Command("rundll32", "url.dll,FileProtocolHandler", logPath())
				open.Start()
			case <-mDoctor.ClickedCh:
				cmd := exec.Command("cmd.exe", "/k", t.exe, "doctor")
				cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x00000010} // CREATE_NEW_CONSOLE
				cmd.Start()
			case <-mList.ClickedCh:
				if err := runElevated(t.exe, "hosts update"); err == nil {
					go func() {
						time.Sleep(15 * time.Second)
						checkList()
					}()
				}
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

// notify shows a Windows toast notification through PowerShell. The text is
// passed in environment variables, never pasted into the script.
func notify(title, msg string) {
	const script = `[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
$t = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$x = $t.GetElementsByTagName('text')
$x.Item(0).AppendChild($t.CreateTextNode($env:SNISPLIT_TITLE)) > $null
$x.Item(1).AppendChild($t.CreateTextNode($env:SNISPLIT_MSG)) > $null
$app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show([Windows.UI.Notifications.ToastNotification]::new($t))`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script)
	cmd.Env = append(os.Environ(), "SNISPLIT_TITLE="+title, "SNISPLIT_MSG="+msg)
	cmd.SysProcAttr = detachAttr()
	cmd.Start()
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
