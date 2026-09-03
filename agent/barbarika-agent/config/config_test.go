package config

import (
	"regexp"
	"testing"
)

var uuidV4 = regexp.MustCompile(
	`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
)

func TestBootIDIsFreshPerStartAndValid(t *testing.T) {
	t.Setenv("BOOT_ID", "") // treated as unset -> generated

	a := LoadConfig().BootID
	b := LoadConfig().BootID

	if a == b {
		t.Fatalf("boot_id should be fresh per process start, got %q twice", a)
	}
	if !uuidV4.MatchString(a) {
		t.Fatalf("boot_id is not a v4 UUID: %q", a)
	}
}

func TestBootIDEnvOverrideWins(t *testing.T) {
	t.Setenv("BOOT_ID", "pinned-boot-id")
	if got := LoadConfig().BootID; got != "pinned-boot-id" {
		t.Fatalf("env override ignored: %q", got)
	}
}
