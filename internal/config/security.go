package config

import "strings"

const (
	SecurityProfileBalanced = "balanced"
	SecurityProfileHard     = "hard"
	SecurityProfileRKNHard  = "rkn-hard"
)

func NormalizeSecurityProfile(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case SecurityProfileHard:
		return SecurityProfileHard
	case SecurityProfileRKNHard, "rkn", "max", "strict":
		return SecurityProfileRKNHard
	default:
		return SecurityProfileBalanced
	}
}

func SecurityProfiles() []string {
	return []string{
		SecurityProfileBalanced,
		SecurityProfileHard,
		SecurityProfileRKNHard,
	}
}

func ProfileBlockedDomains(profile string) []string {
	profile = NormalizeSecurityProfile(profile)
	base := []string{
		"doubleclick.net",
		"googlesyndication.com",
		"googleadservices.com",
		"googletagmanager.com",
		"google-analytics.com",
		"scorecardresearch.com",
		"adnxs.com",
	}
	if profile == SecurityProfileBalanced {
		return nil
	}
	if profile == SecurityProfileHard {
		return base
	}
	return append(base,
		"analytics.google.com",
		"stats.g.doubleclick.net",
		"ads-twitter.com",
		"app-measurement.com",
	)
}

