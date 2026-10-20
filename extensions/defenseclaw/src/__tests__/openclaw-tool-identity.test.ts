// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import type { PluginApi, ToolContext } from "@openclaw/plugin-sdk";
import {
  buildSidecarCorrelationHeaders,
  HEADER_DEFENSECLAW_AGENT_ID,
  HEADER_DEFENSECLAW_OPENCLAW_AGENT_ID,
} from "../correlation-headers.js";

vi.mock("../sidecar-config.js", () => ({
  loadSidecarConfig: () => ({
    baseUrl: "http://127.0.0.1:18899",
    token: "synthetic gateway credential",
    guardrailPort: 18898,
    hiltEnabled: false,
  }),
}));
vi.mock("../aws-sdk-http1-for-guardrail.js", () => ({ patchAwsSdkHttp1ForGuardrail: vi.fn() }));
vi.mock("../fetch-interceptor.js", () => ({
  createFetchInterceptor: () => ({ start: vi.fn(), stop: vi.fn() }),
}));

import pluginSetup from "../index.js";

type ToolHandler = Parameters<PluginApi["on"]>[1];

function setupPlugin(identityReady: Promise<Record<string, unknown>> = Promise.resolve({})) {
  let handler: ToolHandler | undefined;
  const api = {
    on: (_name: string, listener: ToolHandler) => { handler = listener; },
    registerService: vi.fn(),
    registerCommand: vi.fn(),
    getPluginConfig: () => identityReady,
  };
  pluginSetup(api as unknown as PluginApi);
  if (!handler) throw new Error("before_tool_call was not registered");
  return handler;
}

function response(action = "allow") {
  return new Response(JSON.stringify({ action, severity: "HIGH", reason: "synthetic verdict", mode: "action" }));
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("OpenClaw execution agent metadata", () => {
  it("captures each call before plugin initialization resolves, including messages", async () => {
    vi.stubEnv("DEFENSECLAW_AGENT_ID", "shared-plugin");
    let releaseIdentity!: (value: Record<string, unknown>) => void;
    const ready = new Promise<Record<string, unknown>>((resolve) => { releaseIdentity = resolve; });
    const handler = setupPlugin(ready);
    const requests: { headers: Headers; body: Record<string, unknown> }[] = [];
    let releaseMedical!: () => void;
    const medicalResponse = new Promise<void>((resolve) => { releaseMedical = resolve; });
    const completed: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (_url: string, init: RequestInit) => {
      const headers = new Headers(init.headers);
      const body = JSON.parse(String(init.body));
      requests.push({ headers, body });
      const id = headers.get(HEADER_DEFENSECLAW_OPENCLAW_AGENT_ID)!;
      if (id === "medical") await medicalResponse;
      completed.push(id);
      return response();
    }));

    const medical: ToolContext = { agentId: "medical", sessionId: "session-medical", runId: "run-medical", toolName: "exec" };
    const work: ToolContext = { agentId: "work", sessionId: "session-work", runId: "run-work", toolName: "message" };
    const first = handler({ toolName: "exec", params: { command: "printf synthetic" } }, medical);
    const second = handler({ toolName: "message", params: { content: "synthetic message" } }, work);
    medical.agentId = "changed-after-callback";
    work.agentId = "changed-after-callback";
    releaseIdentity({});
    await second;
    expect(completed).toEqual(["work"]);
    releaseMedical();
    await first;

    expect(requests).toHaveLength(2);
    expect(requests.map(({ headers }) => headers.get(HEADER_DEFENSECLAW_OPENCLAW_AGENT_ID))).toEqual(["medical", "work"]);
    for (const { headers, body } of requests) {
      const id = headers.get(HEADER_DEFENSECLAW_OPENCLAW_AGENT_ID);
      expect(headers.get(HEADER_DEFENSECLAW_AGENT_ID)).toBe("shared-plugin");
      expect(headers.get("Authorization")).toBe("Bearer synthetic gateway credential");
      expect(headers.get("X-DefenseClaw-Session-Id")).toBe(`session-${id}`);
      expect(body.session_id).toBe(`session-${id}`);
      expect(body).not.toHaveProperty("agent_id");
    }
  });

  it.each([undefined, "", " medical", "Medical", "medical\n", "work,medical", "équipe", "a".repeat(65)])(
    "omits missing or invalid identity %j without inferring from the session or plugin", async (agentId) => {
      vi.stubEnv("DEFENSECLAW_AGENT_ID", "shared-plugin");
      const fetchMock = vi.fn(async (_url: string, _init: RequestInit) => response());
      vi.stubGlobal("fetch", fetchMock);
      const handler = setupPlugin();
      expect(await handler({ toolName: "exec", params: {} }, {
        agentId, toolName: "exec", sessionKey: "agent:medical:main",
      })).toBeUndefined();
      const headers = new Headers(fetchMock.mock.calls[0][1].headers);
      expect(headers.has(HEADER_DEFENSECLAW_OPENCLAW_AGENT_ID)).toBe(false);
      expect(headers.get(HEADER_DEFENSECLAW_AGENT_ID)).toBe("shared-plugin");
    },
  );

  it.each(["allow", "confirm", "block"])("preserves the %s result for both agents", async (action) => {
    vi.stubGlobal("fetch", vi.fn(async () => response(action)));
    const handler = setupPlugin();
    for (const agentId of ["medical", "work"]) {
      const result = await handler({ toolName: "exec", params: {} }, { agentId, toolName: "exec" });
      if (action === "allow") expect(result).toBeUndefined();
      if (action === "confirm") expect(result).toHaveProperty("requireApproval");
      if (action === "block") expect(result).toMatchObject({ block: true });
    }
  });

  it("accepts canonical IDs at the length boundary without replacing logical identity", () => {
    const headers = buildSidecarCorrelationHeaders({ agentId: "shared-plugin", openclawAgentId: "a".repeat(64) }, { outboundAgentInstanceId: "" });
    expect(headers[HEADER_DEFENSECLAW_OPENCLAW_AGENT_ID]).toHaveLength(64);
    expect(headers[HEADER_DEFENSECLAW_AGENT_ID]).toBe("shared-plugin");
    expect(buildSidecarCorrelationHeaders({ agentId: "shared-plugin" }, { outboundAgentInstanceId: "" }))
      .not.toHaveProperty(HEADER_DEFENSECLAW_OPENCLAW_AGENT_ID);
  });
});
