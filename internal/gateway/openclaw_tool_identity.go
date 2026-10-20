// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
)

// OpenClawAgentIDHeader reports the named execution agent for one OpenClaw
// tool inspection. It must never replace AgentIDHeader's logical plugin identity.
const OpenClawAgentIDHeader = "X-DefenseClaw-OpenClaw-Agent-Id"

type openClawAgentIDContextKey struct{}

// OpenClawAgentIDFromContext returns bounded, connector-reported metadata, or
// empty when absent/invalid/out of scope. OpenClaw supplies ctx.agentId to its
// trusted host plugin, but gateway token/connector authentication does not
// independently authenticate that named agent. Never use this for policy
// selection, authorization, privileges, or session ownership.
func OpenClawAgentIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	id, _ := ctx.Value(openClawAgentIDContextKey{}).(string)
	return id
}

// contextWithOpenClawToolIdentity runs only in the protected tool-inspect
// handler, after the server has resolved the connector. Client-declared
// connector/client headers alone do not establish scope. Invalid values are
// omitted, not repaired/truncated into a different identity or used to change
// the inspection decision.
func contextWithOpenClawToolIdentity(ctx context.Context, header http.Header, connector string) context.Context {
	if connector != "openclaw" {
		return ctx
	}
	values := header.Values(OpenClawAgentIDHeader)
	if len(values) != 1 {
		return ctx
	}
	id := values[0]
	if len(id) == 0 || len(id) > 64 || !openClawAgentIDAlphanumeric(id[0]) {
		return ctx
	}
	for i := 1; i < len(id); i++ {
		if !openClawAgentIDAlphanumeric(id[i]) && id[i] != '_' && id[i] != '-' {
			return ctx
		}
	}
	return context.WithValue(ctx, openClawAgentIDContextKey{}, id)
}

func openClawAgentIDAlphanumeric(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}
