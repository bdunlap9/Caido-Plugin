import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import corsMisconfigCheck from "./index";

describe("cors-misconfig check", () => {
  it("should detect null origin with credentials", async () => {
    const executionHistory = await runCheck(corsMisconfigCheck, [
      {
        request: createMockRequest({ id: "1", host: "example.com", port: 443, method: "GET", path: "/api" }),
        response: createMockResponse({
          id: "r1",
          code: 200,
          headers: {
            "access-control-allow-origin": ["null"],
            "access-control-allow-credentials": ["true"],
            "content-type": ["application/json"],
          },
          body: "{}",
        }),
      },
    ]);

    expect(executionHistory).toHaveLength(1);
    expect(executionHistory[0]?.status).toBe("completed");
    expect(executionHistory[0]?.checkId).toBe("cors-misconfig");
    const findings = executionHistory[0]?.steps.flatMap((s: any) => s.findings) ?? [];
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]?.name).toContain("CORS");
  });

  it("should not detect when wildcard origin without credentials", async () => {
    const executionHistory = await runCheck(corsMisconfigCheck, [
      {
        request: createMockRequest({ id: "5", host: "example.com", port: 443, method: "GET", path: "/api" }),
        response: createMockResponse({
          id: "r5",
          code: 200,
          headers: {
            "access-control-allow-origin": ["*"],
            "content-type": ["application/json"],
          },
          body: "{}",
        }),
      },
    ]);

    expect(executionHistory).toHaveLength(1);
    const findings = executionHistory[0]?.steps.flatMap((s: any) => s.findings) ?? [];
    expect(findings.length).toBe(0);
  });

  it("should not detect when legitimate same-origin CORS", async () => {
    const executionHistory = await runCheck(corsMisconfigCheck, [
      {
        request: createMockRequest({ id: "6", host: "example.com", port: 443, method: "GET", path: "/api" }),
        response: createMockResponse({
          id: "r6",
          code: 200,
          headers: {
            "access-control-allow-origin": ["https://example.com"],
            "access-control-allow-credentials": ["true"],
            "content-type": ["application/json"],
          },
          body: "{}",
        }),
      },
    ]);

    expect(executionHistory).toHaveLength(1);
    const findings = executionHistory[0]?.steps.flatMap((s: any) => s.findings) ?? [];
    expect(findings.length).toBe(0);
  });

  it("should not detect when no CORS headers present", async () => {
    const executionHistory = await runCheck(corsMisconfigCheck, [
      {
        request: createMockRequest({ id: "7", host: "example.com", port: 443, method: "GET", path: "/api" }),
        response: createMockResponse({
          id: "r7",
          code: 200,
          headers: { "content-type": ["application/json"] },
          body: "{}",
        }),
      },
    ]);

    expect(executionHistory).toHaveLength(1);
    expect(executionHistory[0]?.checkId).toBe("cors-misconfig");
    const findings = executionHistory[0]?.steps.flatMap((s: any) => s.findings) ?? [];
    expect(findings.length).toBe(0);
  });

  it("should not detect null origin without credentials", async () => {
    const executionHistory = await runCheck(corsMisconfigCheck, [
      {
        request: createMockRequest({ id: "8", host: "example.com", port: 443, method: "GET", path: "/api" }),
        response: createMockResponse({
          id: "r8",
          code: 200,
          headers: {
            "access-control-allow-origin": ["null"],
            "content-type": ["application/json"],
          },
          body: "{}",
        }),
      },
    ]);

    expect(executionHistory).toHaveLength(1);
    const findings = executionHistory[0]?.steps.flatMap((s: any) => s.findings) ?? [];
    expect(findings.length).toBe(0);
  });
});
