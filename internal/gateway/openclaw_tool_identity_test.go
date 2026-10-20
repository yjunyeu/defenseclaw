// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

func TestOpenClawToolIdentityValidationAndScope(t *testing.T) {
	for _, test := range []struct {
		name, id, connector, want string
	}{
		{"medical", "medical", "openclaw", "medical"},
		{"work", "work", "openclaw", "work"},
		{"canonical punctuation", "agent_2-work", "openclaw", "agent_2-work"},
		{"maximum", strings.Repeat("a", 64), "openclaw", strings.Repeat("a", 64)},
		{"missing", "", "openclaw", ""},
		{"oversized", strings.Repeat("a", 65), "openclaw", ""},
		{"newline", "medical\nforged=true", "openclaw", ""},
		{"trailing newline", "medical\n", "openclaw", ""},
		{"whitespace", " medical", "openclaw", ""},
		{"uppercase", "Medical", "openclaw", ""},
		{"unicode", "médical", "openclaw", ""},
		{"leading punctuation", "-medical", "openclaw", ""},
		{"combined headers", "medical,work", "openclaw", ""},
		{"other connector", "medical", "codex", ""},
		{"unknown connector", "medical", "", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			header := http.Header{}
			header.Set(OpenClawAgentIDHeader, test.id)
			ctx := contextWithOpenClawToolIdentity(context.Background(), header, test.connector)
			if got := OpenClawAgentIDFromContext(ctx); got != test.want {
				t.Fatalf("id=%q want=%q", got, test.want)
			}
		})
	}
	header := http.Header{}
	header.Add(OpenClawAgentIDHeader, "medical")
	header.Add(OpenClawAgentIDHeader, "work")
	if got := OpenClawAgentIDFromContext(contextWithOpenClawToolIdentity(context.Background(), header, "openclaw")); got != "" {
		t.Fatalf("duplicate header accepted: %q", got)
	}
	if OpenClawAgentIDFromContext(nil) != "" {
		t.Fatal("nil context must have absent identity")
	}
}

func newOpenClawIdentityTestAPI(t *testing.T) (*APIServer, *sql.DB, http.Handler) {
	t.Helper()
	fixture := newSidecarRuntimeFixture(t, true)
	logger := audit.NewLogger(fixture.store)
	logger.SetRuntimeV8Emitter(&sidecarOwnedObservabilityV8Runtime{runtime: fixture.runtime})
	cfg := &config.Config{}
	cfg.Gateway.Token = "synthetic gateway credential"
	cfg.Guardrail.Connector = "openclaw"
	cfg.Guardrail.Mode = "action"
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, fixture.store, logger, cfg)
	api.inspectToolScanTimeout = 5 * time.Second
	db, err := sql.Open("sqlite", fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	handler := requestIDMiddleware(CorrelationMiddleware(NewAgentRegistry("shared-plugin", "OpenClaw"))(
		api.tokenAuth(http.HandlerFunc(api.handleInspectTool)),
	))
	return api, db, handler
}

func openClawIdentityTestRequest(id, session, body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer synthetic gateway credential")
	r.Header.Set(AgentIDHeader, "shared-plugin")
	r.Header.Set(SessionIDHeader, session)
	if id != "" {
		r.Header.Set(OpenClawAgentIDHeader, id)
	}
	return r
}

func TestOpenClawToolIdentityConcurrentPersistentAudit(t *testing.T) {
	_, db, handler := newOpenClawIdentityTestAPI(t)
	previousRun := gatewaylog.ProcessRunID()
	gatewaylog.SetProcessRunID("synthetic-inspect-run")
	t.Cleanup(func() { gatewaylog.SetProcessRunID(previousRun) })
	const calls = 8
	start := make(chan struct{})
	var ready, done sync.WaitGroup
	ready.Add(calls)
	done.Add(calls)
	for i := range calls {
		go func() {
			defer done.Done()
			id := []string{"medical", "work"}[i%2]
			tool := []string{"exec", "message"}[(i/2)%2]
			session := fmt.Sprintf("synthetic-%s-%d", id, i)
			body := `{"tool":"exec","args":{"command":"printf synthetic"}}`
			if tool == "message" {
				body = `{"tool":"message","content":"synthetic fixture","direction":"outbound"}`
			}
			r := openClawIdentityTestRequest(id, session, body)
			ready.Done()
			<-start
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			var verdict ToolInspectVerdict
			if err := json.Unmarshal(w.Body.Bytes(), &verdict); err != nil || w.Code != http.StatusOK || verdict.Action != "allow" {
				t.Errorf("%s: status=%d verdict=%+v err=%v", session, w.Code, verdict, err)
			}
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()
	rows, err := db.Query(`SELECT agent_id, session_id, run_id, target, action, structured_json
		FROM audit_events WHERE action = 'inspect-tool-allow'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := map[string]int{}
	count := 0
	for rows.Next() {
		var logical, session, run, tool, action, structured string
		if err := rows.Scan(&logical, &session, &run, &tool, &action, &structured); err != nil {
			t.Fatal(err)
		}
		var metadata map[string]any
		if err := json.Unmarshal([]byte(structured), &metadata); err != nil {
			t.Fatal(err)
		}
		id, _ := metadata["openclaw_agent_id"].(string)
		if (id != "medical" && id != "work") || !strings.HasPrefix(session, "synthetic-"+id+"-") ||
			logical != "shared-plugin" || run != "synthetic-inspect-run" || (tool != "exec" && tool != "message") {
			t.Fatalf("mixed attribution: logical=%q session=%q run=%q tool=%q structured=%s", logical, session, run, tool, structured)
		}
		seen[id+":"+tool]++
		count++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if count != calls || len(seen) != 4 {
		t.Fatalf("persisted=%d combinations=%v", count, seen)
	}
}

func TestOpenClawToolIdentityMissingInvalidAndScopeAudit(t *testing.T) {
	api, db, handler := newOpenClawIdentityTestAPI(t)
	for i, id := range []string{"", "work,medical", strings.Repeat("a", 65), "Medical", "medical\nforged"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, openClawIdentityTestRequest(id, fmt.Sprintf("absent-%d", i), `{"tool":"exec","args":{}}`))
		if w.Code != http.StatusOK {
			t.Fatalf("metadata changed inspection access: %d", w.Code)
		}
	}
	// A claimed client/connector header cannot turn another connector into OpenClaw.
	api.scannerCfg.Guardrail.Connector = "codex"
	r := openClawIdentityTestRequest("medical", "other-connector", `{"tool":"exec","args":{}}`)
	r.Header.Set("X-DefenseClaw-Client", "openclaw-plugin")
	r.Header.Set("X-DefenseClaw-Connector", "openclaw")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("out-of-scope metadata changed inspection: %d", w.Code)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE action = 'inspect-tool-allow'
		AND structured_json LIKE '%openclaw_agent_id%'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("missing/invalid/out-of-scope attribution persisted: count=%d err=%v", count, err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE action = 'inspect-tool-allow'`).Scan(&count); err != nil || count != 6 {
		t.Fatalf("missing audit decisions: count=%d err=%v", count, err)
	}
}

func TestOpenClawToolIdentityDoesNotAuthorizeOrSelectPolicy(t *testing.T) {
	api, db, handler := newOpenClawIdentityTestAPI(t)
	for _, credential := range []string{"", "Bearer invalid synthetic credential"} {
		r := openClawIdentityTestRequest("work", "unauthenticated", `{"tool":"exec","args":{}}`)
		r.Header.Set("Authorization", credential)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("spoofed identity bypassed authentication: %d", w.Code)
		}
	}
	var unauthorizedInspections int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE action LIKE 'inspect-tool-%'`).Scan(&unauthorizedInspections); err != nil || unauthorizedInspections != 0 {
		t.Fatalf("unauthenticated inspection persisted: count=%d err=%v", unauthorizedInspections, err)
	}
	if err := enforce.NewPolicyEngine(api.store).BlockToolForConnector("fixture_denied", "openclaw", "synthetic block"); err != nil {
		t.Fatal(err)
	}
	api.scannerCfg.Guardrail.HILT.Enabled = true
	api.scannerCfg.Guardrail.HILT.MinSeverity = "HIGH"
	for _, test := range []struct{ body, want string }{
		{`{"tool":"exec","args":{"command":"printf synthetic"}}`, "allow"},
		{`{"tool":"fixture_denied","args":{}}`, "block"},
		{`{"tool":"shell","args":{"command":"chmod 777 /etc/shadow"},"approval_surface":"native"}`, "confirm"},
	} {
		var baseline ToolInspectVerdict
		for i, id := range []string{"", "medical", "work", "unknown-agent", "spoofed-agent"} {
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, openClawIdentityTestRequest(id, "decision-"+id, test.body))
			var verdict ToolInspectVerdict
			if err := json.Unmarshal(w.Body.Bytes(), &verdict); err != nil || w.Code != http.StatusOK || verdict.Action != test.want {
				t.Fatalf("id=%q want=%s status=%d verdict=%+v err=%v", id, test.want, w.Code, verdict, err)
			}
			if i == 0 {
				baseline = verdict
			} else if !reflect.DeepEqual(baseline, verdict) {
				t.Fatalf("identity changed verdict: baseline=%+v id=%q verdict=%+v", baseline, id, verdict)
			}
		}
	}
}
