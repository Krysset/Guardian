package api

import "strings"

// describeUserAgent turns a User-Agent header into "Firefox on Windows", for the sessions page. It knows
// the common browsers and systems; anything else is "Unknown browser". The order of the checks matters:
// Edge and Opera also claim to be Chrome, and Chrome claims to be Safari.
func describeUserAgent(ua string) string {
	if ua == "" {
		return "Unknown browser"
	}
	browser := ""
	for _, b := range []struct{ token, name string }{
		{"Edg/", "Edge"}, {"EdgA/", "Edge"}, {"EdgiOS/", "Edge"},
		{"OPR/", "Opera"}, {"Opera", "Opera"},
		{"SamsungBrowser/", "Samsung Internet"},
		{"Vivaldi/", "Vivaldi"},
		{"Firefox/", "Firefox"}, {"FxiOS/", "Firefox"},
		{"CriOS/", "Chrome"}, {"Chromium/", "Chromium"}, {"Chrome/", "Chrome"},
		{"Safari/", "Safari"},
		{"curl/", "curl"},
	} {
		if strings.Contains(ua, b.token) {
			browser = b.name
			break
		}
	}
	system := ""
	for _, s := range []struct{ token, name string }{
		{"iPhone", "iPhone"}, {"iPad", "iPad"},
		{"Android", "Android"},
		{"CrOS", "ChromeOS"},
		{"Windows", "Windows"},
		{"Mac OS X", "macOS"}, {"Macintosh", "macOS"},
		{"Linux", "Linux"},
	} {
		if strings.Contains(ua, s.token) {
			system = s.name
			break
		}
	}
	switch {
	case browser == "" && system == "":
		return "Unknown browser"
	case browser == "":
		return "A browser on " + system
	case system == "":
		return browser
	}
	return browser + " on " + system
}
