//go:build ignore

// backlog_graph.go — the BACKLOG tool. Single source of truth is the per-ticket
// `Links:` lines in BACKLOG.md; everything here is a DERIVED view of that graph.
//
//   go run tools/backlog_graph.go                 # emit the generated graph block (default)
//   go run tools/backlog_graph.go -check          # validate integrity (non-zero exit on problems)
//   go run tools/backlog_graph.go ready           # actionable tickets with all blockers done
//   go run tools/backlog_graph.go blocked         # actionable tickets with a pending blocker
//   go run tools/backlog_graph.go deferred|done   # by status
//   go run tools/backlog_graph.go show  T-019     # one ticket's full neighborhood
//   go run tools/backlog_graph.go path  T-021     # transitive prerequisite (blocked-by) tree
//   go run tools/backlog_graph.go repl            # gentle line-based ANSI REPL (no raw mode)
//   go run tools/backlog_graph.go export          # bash script that creates GitHub issues (review before running)
//
// Stdlib only. ANSI color auto-off when stdout is not a TTY or NO_COLOR is set.
// Parsing stops at the BEGIN GENERATED marker so the generated block is never re-parsed.

package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

var (
	reHeading  = regexp.MustCompile(`\*\*(T-\d{3})(?: — (.+?)\*\* — \*(.+?)\*)?`)
	reLinks    = regexp.MustCompile(`(?i)^\s*Links:\s*(.+)$`)
	rePriority = regexp.MustCompile(`(?i)^\s*Priority:\s*(\S+)`)
	rePhase    = regexp.MustCompile(`^##\s+Phase\s+(\d)`)
	reTicket   = regexp.MustCompile(`T-\d{3}`)
)

var inverse = map[string]string{
	"blocked-by": "blocks", "composes": "composed-by", "spawned-by": "spawned",
	"supersedes": "superseded-by", "informed-by": "informs", "related": "related",
	"child-of": "parent-of",
}
var verbOrder = []string{
	"blocked-by", "blocks", "child-of", "parent-of", "composes", "composed-by",
	"spawned-by", "spawned", "supersedes", "superseded-by", "informed-by", "informs", "related",
}

type edge struct{ verb, to string }
type ticket struct {
	id, title, status, statusRaw, priority string
	phase                                  int
	links                                  []edge
	body                                   []string
}

// ---- color ----

var useColor = true

func col(code, s string) string {
	if !useColor || code == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}
func statusColor(st string) string {
	switch st {
	case "done":
		return "32" // green
	case "started":
		return "33" // yellow
	case "open":
		return "36" // cyan
	case "exploratory":
		return "35" // magenta
	case "deferred":
		return "90" // gray
	case "blocked":
		return "31" // red
	}
	return ""
}
func isTTY() bool {
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// priority: P0 (showstopper) → P4 (trivial), spectrum gradient red→orange→yellow→green→blue.
func priorityColor(p string) string {
	switch p {
	case "P0":
		return "1;31" // bold red — showstopper
	case "P1":
		return "38;5;208" // orange
	case "P2":
		return "33" // yellow
	case "P3":
		return "32" // green
	case "P4":
		return "34" // blue
	}
	return ""
}
func prioRank(p string) int {
	switch p {
	case "P0":
		return 0
	case "P1":
		return 1
	case "P2":
		return 2
	case "P3":
		return 3
	case "P4":
		return 4
	}
	return 9 // unset sorts last
}

func classify(raw string) string {
	s := strings.ToUpper(raw)
	switch {
	case strings.Contains(s, "STARTED"), strings.Contains(s, "IN PROGRESS"), strings.Contains(s, "IN-PROGRESS"):
		return "started"
	case strings.Contains(s, "OPEN"):
		return "open"
	case strings.Contains(s, "DONE"), strings.Contains(s, "CONFIRMED"):
		return "done"
	case strings.Contains(s, "EXPLORATORY"):
		return "exploratory"
	case strings.Contains(s, "DEFERRED"), strings.Contains(s, "FUTURE"):
		return "deferred"
	}
	return "unknown"
}

func actionable(t *ticket) bool {
	return t.status == "started" || t.status == "open" || t.status == "exploratory"
}

// ---- parse ----

func parse(path string) ([]*ticket, map[string]*ticket, []string) {
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: cannot read backlog %q: %v\n", path, err)
		os.Exit(1)
	}
	defer f.Close()

	var order []*ticket
	byID := map[string]*ticket{}
	var cur *ticket
	phase := 0

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.Contains(line, "BEGIN GENERATED") {
			break
		}
		if strings.HasPrefix(line, "## ") {
			if m := rePhase.FindStringSubmatch(line); m != nil {
				phase = int(m[1][0] - '0')
			} else {
				phase = 0 // non-phase section (e.g., Tooling)
			}
			continue
		}
		if m := reHeading.FindStringSubmatch(line); m != nil {
			cur = &ticket{id: m[1], title: m[2], statusRaw: m[3], phase: phase}
			cur.status = classify(m[3])
			if _, dup := byID[cur.id]; !dup {
				order = append(order, cur)
				byID[cur.id] = cur
			}
			continue
		}
		if cur == nil {
			continue
		}
		if m := rePriority.FindStringSubmatch(line); m != nil {
			cur.priority = strings.ToUpper(m[1])
			continue
		}
		if m := reLinks.FindStringSubmatch(line); m != nil {
			for _, part := range strings.Split(m[1], ";") {
				kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
				if len(kv) != 2 {
					continue
				}
				v := strings.TrimSpace(kv[0])
				for _, to := range reTicket.FindAllString(kv[1], -1) {
					cur.links = append(cur.links, edge{v, to})
				}
			}
			continue
		}
		if t := strings.TrimSpace(line); t != "" {
			cur.body = append(cur.body, t)
		}
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}

	// schema integrity (every ticket conforms) + edge integrity
	var problems []string
	for _, t := range order {
		switch {
		case t.title == "":
			problems = append(problems, t.id+": malformed heading (missing title/status — expected `**T-NNN — Title** — *status*`)")
		case t.status == "unknown":
			problems = append(problems, fmt.Sprintf("%s: unrecognized status %q", t.id, t.statusRaw))
		}
		if t.priority != "" && prioRank(t.priority) == 9 {
			problems = append(problems, fmt.Sprintf("%s: invalid priority %q (want P0..P4)", t.id, t.priority))
		}
		for _, e := range t.links {
			switch {
			case byID[e.to] == nil:
				problems = append(problems, fmt.Sprintf("%s: dangling ref %s (%s)", t.id, e.to, e.verb))
			case e.to == t.id:
				problems = append(problems, fmt.Sprintf("%s: self-loop (%s)", t.id, e.verb))
			case inverse[e.verb] == "":
				problems = append(problems, fmt.Sprintf("%s: unknown verb %q", t.id, e.verb))
			}
		}
	}
	problems = append(problems, blockedByCycles(order)...)
	return order, byID, problems
}

func adjacency(order []*ticket) map[string]map[string][]string {
	adj := map[string]map[string][]string{}
	add := func(from, verb, to string) {
		if adj[from] == nil {
			adj[from] = map[string][]string{}
		}
		for _, x := range adj[from][verb] {
			if x == to {
				return
			}
		}
		adj[from][verb] = append(adj[from][verb], to)
	}
	for _, t := range order {
		for _, e := range t.links {
			if inverse[e.verb] == "" || e.to == t.id {
				continue
			}
			add(t.id, e.verb, e.to)
			add(e.to, inverse[e.verb], t.id)
		}
	}
	return adj
}

// ---- views ----

func tag(t *ticket) string {
	return col(statusColor(t.status), fmt.Sprintf("%-11s", t.status))
}
func line(t *ticket) string {
	return fmt.Sprintf("%s  %s  %s", col("1", t.id), tag(t), t.title)
}
func prioLine(t *ticket) string {
	p, code := t.priority, priorityColor(t.priority)
	if p == "" {
		p, code = "P_", "90" // unknown priority — dimmed, never silent
	}
	return fmt.Sprintf("%s  %s", col(code, fmt.Sprintf("%-3s", p)), line(t))
}
func byPriority(ts []*ticket) {
	sort.SliceStable(ts, func(i, j int) bool { return prioRank(ts[i].priority) < prioRank(ts[j].priority) })
}

// lackingPriority returns actionable tickets with no priority set (done/deferred
// don't need one). warnNoPriority surfaces the count + set as a soft warning (not a
// hard schema failure). Future: infer a hint from linked tickets' priorities — deferred
// while the set is mostly empty (it would just propagate P_).
// an epic (a ticket with children) isn't directly workable — you work its children.
func hasChildren(id string, adj map[string]map[string][]string) bool {
	return len(adj[id]["parent-of"]) > 0
}
func lackingPriority(order []*ticket, adj map[string]map[string][]string) []string {
	var ids []string
	for _, t := range order {
		if actionable(t) && !hasChildren(t.id, adj) && t.priority == "" {
			ids = append(ids, t.id)
		}
	}
	return ids
}
func warnNoPriority(order []*ticket, adj map[string]map[string][]string) {
	if miss := lackingPriority(order, adj); len(miss) > 0 {
		fmt.Printf("  %s %d actionable ticket(s) lack a priority (P_): %s\n",
			col("33", "⚠"), len(miss), strings.Join(miss, " "))
	}
}

func pendingBlockers(t *ticket, byID map[string]*ticket, adj map[string]map[string][]string) []string {
	var pend []string
	for _, b := range adj[t.id]["blocked-by"] {
		if bt := byID[b]; bt != nil && bt.status != "done" {
			pend = append(pend, b)
		}
	}
	sort.Strings(pend)
	return pend
}

func viewReady(order []*ticket, byID map[string]*ticket, adj map[string]map[string][]string) {
	fmt.Println(col("1", "READY — actionable, all blockers done (by priority):"))
	var rs []*ticket
	for _, t := range order {
		if actionable(t) && !hasChildren(t.id, adj) && len(pendingBlockers(t, byID, adj)) == 0 {
			rs = append(rs, t)
		}
	}
	byPriority(rs)
	if len(rs) == 0 {
		fmt.Println("  (none)")
		return
	}
	for _, t := range rs {
		fmt.Println("  " + prioLine(t))
	}
	warnNoPriority(order, adj)
}

func viewPrio(order []*ticket, adj map[string]map[string][]string) {
	fmt.Println(col("1", "BY PRIORITY (actionable, epics excluded):"))
	var acts []*ticket
	for _, t := range order {
		if actionable(t) && !hasChildren(t.id, adj) {
			acts = append(acts, t)
		}
	}
	byPriority(acts)
	if len(acts) == 0 {
		fmt.Println("  (none)")
		return
	}
	for _, t := range acts {
		fmt.Println("  " + prioLine(t))
	}
	warnNoPriority(order, adj)
}

func viewBlocked(order []*ticket, byID map[string]*ticket, adj map[string]map[string][]string) {
	fmt.Println(col("1", "BLOCKED — actionable, waiting on a prerequisite:"))
	n := 0
	for _, t := range order {
		if !actionable(t) {
			continue
		}
		if pend := pendingBlockers(t, byID, adj); len(pend) > 0 {
			fmt.Printf("  %s  %s %s\n", line(t), col("31", "needs"), strings.Join(pend, ","))
			n++
		}
	}
	if n == 0 {
		fmt.Println("  " + col("32", "(nothing blocked — the actionable frontier is clear)"))
	}
}

func viewStatus(order []*ticket, want string) {
	fmt.Println(col("1", strings.ToUpper(want)+":"))
	n := 0
	for _, t := range order {
		if t.status == want {
			fmt.Println("  " + line(t))
			n++
		}
	}
	if n == 0 {
		fmt.Println("  (none)")
	}
}

func viewBoard(order []*ticket, byID map[string]*ticket, adj map[string]map[string][]string) {
	groups := map[string][]string{}
	for _, t := range order {
		groups[t.status] = append(groups[t.status], t.id)
	}
	rows := []struct{ st, label string }{
		{"started", "in flight"}, {"open", "open"}, {"exploratory", "exploratory"},
		{"deferred", "deferred / backlog"}, {"done", "done"},
	}
	fmt.Println(col("1", fmt.Sprintf("BACKLOG BOARD — %d tickets", len(order))))
	for _, r := range rows {
		ids := groups[r.st]
		sort.Strings(ids)
		fmt.Printf("  %s %2d  %s\n", col(statusColor(r.st), fmt.Sprintf("%-18s", r.label)), len(ids), strings.Join(ids, " "))
	}
	ready, blocked := 0, 0
	for _, t := range order {
		if !actionable(t) || hasChildren(t.id, adj) {
			continue
		}
		if len(pendingBlockers(t, byID, adj)) == 0 {
			ready++
		} else {
			blocked++
		}
	}
	fmt.Printf("  %s ready, %s blocked  (of the actionable frontier)\n",
		col("32", fmt.Sprintf("%d", ready)), col("31", fmt.Sprintf("%d", blocked)))
	warnNoPriority(order, adj)
}

func viewLegend() {
	fmt.Println(col("1", "status color legend:"))
	for _, it := range []struct{ st, desc string }{
		{"started", "in flight"}, {"open", "open / actionable"}, {"exploratory", "exploratory"},
		{"deferred", "deferred / backlog / future"}, {"done", "complete"},
		{"blocked", "computed: actionable with a pending blocker"},
	} {
		fmt.Printf("  %s  %s\n", col(statusColor(it.st), fmt.Sprintf("%-11s", it.st)), it.desc)
	}
	fmt.Println(col("1", "priority color legend:"))
	for _, it := range []struct{ p, desc string }{
		{"P0", "showstopper"}, {"P1", "high"}, {"P2", "medium"}, {"P3", "low"}, {"P4", "trivial"},
	} {
		fmt.Printf("  %s  %s\n", col(priorityColor(it.p), it.p), it.desc)
	}
	fmt.Printf("  %s  unset / unknown\n", col("90", "P_"))
}

func viewShow(byID map[string]*ticket, adj map[string]map[string][]string, id string) {
	t := byID[id]
	if t == nil {
		fmt.Println(col("31", "no such ticket: "+id))
		return
	}
	fmt.Println(line(t))
	pr, pc := t.priority, priorityColor(t.priority)
	if pr == "" {
		pr, pc = "P_", "90"
	}
	if t.phase > 0 {
		fmt.Printf("  phase %d · priority %s · %s\n", t.phase, col(pc, pr), t.statusRaw)
	}
	for _, v := range verbOrder {
		if tos := adj[id][v]; len(tos) > 0 {
			sort.Strings(tos)
			fmt.Printf("  %-14s %s\n", v, strings.Join(tos, ", "))
		}
	}
}

func viewPath(byID map[string]*ticket, adj map[string]map[string][]string, id string) {
	t := byID[id]
	if t == nil {
		fmt.Println(col("31", "no such ticket: "+id))
		return
	}
	fmt.Println(col("1", "PREREQUISITES of "+id+" (transitive blocked-by):"))
	seen := map[string]bool{}
	var walk func(string, int)
	walk = func(cur string, depth int) {
		bs := append([]string(nil), adj[cur]["blocked-by"]...)
		sort.Strings(bs)
		for _, b := range bs {
			mark := col("32", "✓")
			if bt := byID[b]; bt != nil && bt.status != "done" {
				mark = col("31", "·")
			}
			fmt.Printf("  %s%s %s %s\n", strings.Repeat("  ", depth), mark, b, byID[b].title)
			if !seen[b] {
				seen[b] = true
				walk(b, depth+1)
			}
		}
	}
	walk(id, 0)
	if len(adj[id]["blocked-by"]) == 0 {
		fmt.Println("  " + col("32", "(no prerequisites — ready)"))
	}
}

// graphBlock renders the generated graph view as a string (so `graph` prints it and
// `verify` can diff it against the committed block — one emitter, no second copy).
func graphBlock(order []*ticket, adj map[string]map[string][]string) string {
	ids := make([]string, len(order))
	for i, t := range order {
		ids[i] = t.id
	}
	sort.Strings(ids)
	var b strings.Builder
	b.WriteString("## Linkages — generated graph view\n\n")
	b.WriteString("*Derived from the per-ticket `Links:` lines by `tools/backlog_graph.go`. Do not hand-edit:\n")
	b.WriteString("edit the `Links:` line on the ticket and regenerate.*\n\n")
	for _, id := range ids {
		if adj[id] == nil {
			continue
		}
		var parts []string
		for _, v := range verbOrder {
			if tos := adj[id][v]; len(tos) > 0 {
				sort.Strings(tos)
				parts = append(parts, fmt.Sprintf("%s %s", v, strings.Join(tos, ",")))
			}
		}
		if len(parts) > 0 {
			fmt.Fprintf(&b, "- **%s** — %s\n", id, strings.Join(parts, " · "))
		}
	}
	return b.String()
}

// verifyFresh checks the committed generated block matches the current Links: graph
// (read-only staleness gate). Non-zero exit if stale.
func verifyFresh(path string, order []*ticket, adj map[string]map[string][]string) {
	want := strings.TrimSpace(graphBlock(order, adj))
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: cannot read backlog %q: %v\n", path, err)
		os.Exit(1)
	}
	var got []string
	in := false
	for _, ln := range strings.Split(string(data), "\n") {
		switch {
		case strings.Contains(ln, "BEGIN GENERATED"):
			in = true
		case strings.Contains(ln, "END GENERATED"):
			in = false
		case in:
			got = append(got, ln)
		}
	}
	if strings.TrimSpace(strings.Join(got, "\n")) == want {
		fmt.Println("backlog graph view is FRESH (matches the Links: graph)")
		return
	}
	fmt.Fprintln(os.Stderr, "STALE: generated block does not match the current Links: graph.")
	fmt.Fprintln(os.Stderr, "  regenerate in place: go run tools/backlog_graph.go regen")
	os.Exit(1)
}

// regenInPlace rewrites the BEGIN/END GENERATED block in BACKLOG.md in place.
func regenInPlace(path string, order []*ticket, adj map[string]map[string][]string) {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: cannot read backlog %q: %v\n", path, err)
		os.Exit(1)
	}
	block := strings.TrimRight(graphBlock(order, adj), "\n")
	var out []string
	in, sawBegin, sawEnd := false, false, false
	for _, ln := range strings.Split(string(data), "\n") {
		switch {
		case strings.Contains(ln, "BEGIN GENERATED"):
			out = append(out, ln, block)
			in, sawBegin = true, true
		case strings.Contains(ln, "END GENERATED"):
			in, sawEnd = false, true
			out = append(out, ln)
		case !in:
			out = append(out, ln)
		}
	}
	if !sawBegin || !sawEnd {
		fmt.Fprintf(os.Stderr, "ERROR: BEGIN/END GENERATED markers not found in %q\n", path)
		os.Exit(1)
	}
	if err := os.WriteFile(path, []byte(strings.Join(out, "\n")), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: cannot write backlog %q: %v\n", path, err)
		os.Exit(1)
	}
	fmt.Printf("regenerated graph block in %s (%d tickets)\n", path, len(order))
}

// blockedByCycles reports any dependency cycle in the blocked-by edges (must be a DAG).
func blockedByCycles(order []*ticket) []string {
	g := map[string][]string{}
	for _, t := range order {
		for _, e := range t.links {
			if e.verb == "blocked-by" {
				g[t.id] = append(g[t.id], e.to)
			}
		}
	}
	const white, gray, black = 0, 1, 2
	color := map[string]int{}
	var probs, stack []string
	var dfs func(string)
	dfs = func(n string) {
		color[n] = gray
		stack = append(stack, n)
		for _, m := range g[n] {
			switch color[m] {
			case gray:
				probs = append(probs, "blocked-by cycle: "+strings.Join(append(append([]string(nil), stack...), m), " → "))
			case white:
				dfs(m)
			}
		}
		stack = stack[:len(stack)-1]
		color[n] = black
	}
	for _, t := range order {
		if color[t.id] == white {
			dfs(t.id)
		}
	}
	return probs
}

// ---- GitHub issue export ----

func phaseLabel(p int) string {
	if p == 0 {
		return "phase:meta"
	}
	return fmt.Sprintf("phase:%d", p)
}

func exportGH(order []*ticket, adj map[string]map[string][]string) {
	fmt.Println("#!/usr/bin/env bash")
	fmt.Println("# GENERATED by tools/backlog_graph.go export — REVIEW before running.")
	fmt.Println("# Creates GitHub issues from BACKLOG.md: maps T-NNN -> #issue, labels by phase/status,")
	fmt.Println("# wires blocked-by as references (pass 2), closes done tickets (pass 3).")
	fmt.Println("# Requires an authenticated `gh` in the target repo.")
	fmt.Println("set -euo pipefail")
	fmt.Println("declare -A ISSUE")
	fmt.Println()
	fmt.Println("# ensure labels exist (idempotent)")
	labels := map[string]bool{}
	for _, t := range order {
		labels[phaseLabel(t.phase)] = true
		labels["status:"+t.status] = true
		if t.priority != "" {
			labels["priority:"+t.priority] = true
		}
	}
	var ls []string
	for l := range labels {
		ls = append(ls, l)
	}
	sort.Strings(ls)
	for _, l := range ls {
		fmt.Printf("gh label create %q --force >/dev/null 2>&1 || true\n", l)
	}
	fmt.Println()
	fmt.Println("# pass 1 — create issues, capture numbers")
	for _, t := range order {
		title := fmt.Sprintf("%s: %s", t.id, t.title)
		labelArgs := fmt.Sprintf("--label %q --label %q", phaseLabel(t.phase), "status:"+t.status)
		if t.priority != "" {
			labelArgs += fmt.Sprintf(" --label %q", "priority:"+t.priority)
		}
		fmt.Printf("ISSUE[%s]=$(gh issue create --title %q %s --body \"$(cat <<'BODY'\n",
			t.id, title, labelArgs)
		fmt.Printf("Status: %s\n\n", t.statusRaw)
		for _, b := range t.body {
			fmt.Println(b)
		}
		fmt.Println("BODY\n)\" | sed 's#.*/##')")
	}
	fmt.Println()
	fmt.Println("# pass 2 — dependency references (blocked-by) now that numbers exist")
	for _, t := range order {
		bs := append([]string(nil), adj[t.id]["blocked-by"]...)
		sort.Strings(bs)
		if len(bs) == 0 {
			continue
		}
		refs := make([]string, len(bs))
		for i, b := range bs {
			refs[i] = "#${ISSUE[" + b + "]}"
		}
		fmt.Printf("gh issue comment \"${ISSUE[%s]}\" --body \"Blocked by %s\"\n", t.id, strings.Join(refs, " "))
	}
	fmt.Println()
	fmt.Println("# pass 3 — close completed tickets")
	for _, t := range order {
		if t.status == "done" {
			fmt.Printf("gh issue close \"${ISSUE[%s]}\" --reason completed\n", t.id)
		}
	}
}

// ---- REPL ----

func repl(order []*ticket, byID map[string]*ticket, adj map[string]map[string][]string) {
	help := func() {
		fmt.Println(col("90", "commands: board · prio · ready · blocked · started · deferred · done · show <id> · path <id> · legend · all · help · quit"))
	}
	fmt.Println(col("1", "svgsteg backlog — type a command (help, quit)"))
	help()
	in := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print(col("36", "backlog> "))
		if !in.Scan() {
			if err := in.Err(); err != nil {
				fmt.Fprintln(os.Stderr, "input error:", err)
			}
			fmt.Println()
			return
		}
		f := strings.Fields(strings.TrimSpace(in.Text()))
		if len(f) == 0 {
			continue
		}
		arg := ""
		if len(f) > 1 {
			arg = strings.ToUpper(f[1])
		}
		switch f[0] {
		case "quit", "q", "exit":
			return
		case "help", "h", "?":
			help()
		case "board":
			viewBoard(order, byID, adj)
		case "prio", "priority":
			viewPrio(order, adj)
		case "legend":
			viewLegend()
		case "ready":
			viewReady(order, byID, adj)
		case "blocked":
			viewBlocked(order, byID, adj)
		case "done", "deferred", "open", "started", "exploratory":
			viewStatus(order, f[0])
		case "all":
			for _, t := range order {
				fmt.Println("  " + line(t))
			}
		case "show":
			viewShow(byID, adj, arg)
		case "path":
			viewPath(byID, adj, arg)
		default:
			if byID[strings.ToUpper(f[0])] != nil {
				viewShow(byID, adj, strings.ToUpper(f[0]))
			} else {
				fmt.Println(col("31", "unknown command: "+f[0]))
				help()
			}
		}
	}
}

func main() {
	// backlog path: default BACKLOG.md (its expected location), override via
	// $BACKLOG_FILE or -f/--file <path>. Flags are stripped from the positional args.
	path := os.Getenv("BACKLOG_FILE")
	if path == "" {
		path = "BACKLOG.md"
	}
	var pos []string
	for i := 1; i < len(os.Args); i++ {
		a := os.Args[i]
		switch {
		case a == "-f" || a == "--file":
			if i+1 < len(os.Args) {
				path = os.Args[i+1]
				i++
			}
		case strings.HasPrefix(a, "--file="):
			path = strings.TrimPrefix(a, "--file=")
		case strings.HasPrefix(a, "-f="):
			path = strings.TrimPrefix(a, "-f=")
		default:
			pos = append(pos, a)
		}
	}
	mode := "graph"
	if len(pos) > 0 {
		mode = strings.TrimPrefix(pos[0], "-")
	}
	var arg string
	if len(pos) > 1 {
		arg = strings.ToUpper(pos[1])
	}
	useColor = os.Getenv("NO_COLOR") == "" && isTTY()

	order, byID, problems := parse(path)

	// zero tickets is a first-class outcome: there is nothing to consume.
	if len(order) == 0 {
		fmt.Fprintf(os.Stderr, "ERROR: no tickets found in %q (expected `**T-NNN — Title** — *status*` headings) — nothing to do\n", path)
		os.Exit(1)
	}

	if mode != "check" && len(problems) > 0 {
		for _, p := range problems {
			fmt.Fprintln(os.Stderr, "  PROBLEM: "+p)
		}
		os.Exit(1)
	}
	adj := adjacency(order)

	switch mode {
	case "check":
		if len(problems) > 0 {
			for _, p := range problems {
				fmt.Fprintln(os.Stderr, "  PROBLEM: "+p)
			}
			os.Exit(1)
		}
		fmt.Printf("backlog graph OK: %d tickets, no dangling refs / self-loops / unknown verbs\n", len(order))
	case "graph":
		fmt.Print(graphBlock(order, adj))
	case "regen", "write":
		regenInPlace(path, order, adj)
	case "verify":
		verifyFresh(path, order, adj)
	case "board":
		viewBoard(order, byID, adj)
	case "prio", "priority":
		viewPrio(order, adj)
	case "legend":
		viewLegend()
	case "ready":
		viewReady(order, byID, adj)
	case "blocked":
		viewBlocked(order, byID, adj)
	case "done", "deferred", "open", "started", "exploratory":
		viewStatus(order, mode)
	case "show":
		viewShow(byID, adj, arg)
	case "path":
		viewPath(byID, adj, arg)
	case "repl":
		repl(order, byID, adj)
	case "export":
		exportGH(order, adj)
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q (try: graph check verify board prio legend ready blocked started deferred done show path repl export)\n", mode)
		os.Exit(2)
	}
}
