package egress

import "testing"

// routeCategory mirrors the real egress path: classify the line, then tag its
// CERT-In category. Lines below are Anishka's exact rule fixtures
// (rules/tests/fixtures) so the agent's routing stays in lockstep with the
// rules that actually fire (rules/TELEMETRY_CONTRACT.md).
func routeCategory(source, raw string) string {
	if c := candidateCategory(classifyEventType(source, raw), raw); c != nil {
		return *c
	}
	return ""
}

func TestCandidateCategoryRouting(t *testing.T) {
	cases := []struct {
		name   string
		source string
		raw    string
		want   string
	}{
		// Category (x): app-layer exploitation — one line is enough.
		{"sqli_union_sqlmap", "nginx",
			`185.220.101.4 - - [25/Aug/2026:09:15:04 +0000] "GET /shop/index.php?category=1%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" 500 512 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"`,
			"x"},
		// x wins ties: traversal + .git are in both sets but route to x.
		{"traversal_wins_x", "nginx",
			`10.0.0.1 - - [25/Aug/2026:09:20:00 +0000] "GET /../../../../etc/passwd HTTP/1.1" 404 0 "-" "curl/8"`,
			"x"},

		// Category (iv) arm A: defacement-oriented probe (no x signature).
		{"wp_admin_probe", "nginx",
			`185.220.101.9 - - [26/Aug/2026:14:03:00 +0000] "POST /wp-admin/admin-ajax.php?action=upload HTTP/1.1" 200 31 "-" "python-requests/2.32"`,
			"iv"},
		{"webshell_upload", "nginx",
			`185.220.101.9 - - [26/Aug/2026:14:03:05 +0000] "GET /wp-content/uploads/2026/08/shell.php?cmd=id HTTP/1.1" 200 44 "-" "curl/8.7.1"`,
			"iv"},

		// Benign catalogue traffic: "union"/"select"/numeric id are not attacks.
		{"benign_union_word", "nginx",
			`198.51.100.7 - - [25/Aug/2026:11:00:00 +0000] "GET /products/european-union-flags?id=42 HTTP/1.1" 200 3120 "-" "Mozilla/5.0"`,
			""},
		{"benign_select_path", "nginx",
			`198.51.100.7 - - [25/Aug/2026:11:00:03 +0000] "GET /blog/how-to-select-a-router HTTP/1.1" 200 8210 "-" "Mozilla/5.0"`,
			""},
		{"benign_numeric_id", "nginx",
			`198.51.100.7 - - [25/Aug/2026:11:00:07 +0000] "GET /api/v1/users?id=1 HTTP/1.1" 200 561 "-" "Mozilla/5.0"`,
			""},

		// Category (iii): SSH/sudo (content-independent tag).
		{"ssh_failed", "auth", `sshd[9901]: Failed password for root from 185.220.101.4 port 41001 ssh2`, "iii"},
		{"ssh_accepted", "auth", `sshd[9907]: Accepted password for ubuntu from 185.220.101.4 port 4107 ssh2`, "iii"},
		{"sudo", "auth", `sudo:   ubuntu : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/bin/bash`, "iii"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := routeCategory(tc.source, tc.raw); got != tc.want {
				t.Fatalf("routeCategory(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}
