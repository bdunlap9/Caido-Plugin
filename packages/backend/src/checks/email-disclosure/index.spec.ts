import {
  createMockRequest,
  createMockResponse,
  runCheck,
  ScanAggressivity,
} from "engine";
import { describe, expect, it } from "vitest";

import emailDisclosureScan from "./index";

describe("Email Disclosure Check", () => {
  it("should detect email addresses in response", async () => {
    const request = createMockRequest({
      id: "1",
      host: "targetsite.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "Contact us at admin@targetsite.com for support",
    });

    const executionHistory = await runCheck(
      emailDisclosureScan,
      [{ request, response }],
      {
        sendHandler: () => Promise.resolve({ request, response }),
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "email-disclosure",
        targetRequestId: "1",
        status: "completed",
        steps: [
          {
            stepName: "scan",
            findings: [
              {
                name: "Email address disclosure",
                severity: "low",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect multiple email addresses", async () => {
    const request = createMockRequest({
      id: "2",
      host: "targetsite.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "2",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "Contact admin@targetsite.com or support@company.org for help",
    });

    const executionHistory = await runCheck(
      emailDisclosureScan,
      [{ request, response }],
      {
        sendHandler: () => Promise.resolve({ request, response }),
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "email-disclosure",
        targetRequestId: "2",
        status: "completed",
        steps: [
          {
            stepName: "scan",
            findings: [
              {
                name: "Email address disclosure",
                severity: "low",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect international domain emails", async () => {
    const request = createMockRequest({
      id: "3",
      host: "targetsite.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "3",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "Contact us at user@company.co.uk",
    });

    const executionHistory = await runCheck(
      emailDisclosureScan,
      [{ request, response }],
      {
        sendHandler: () => Promise.resolve({ request, response }),
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "email-disclosure",
        targetRequestId: "3",
        status: "completed",
        steps: [
          {
            stepName: "scan",
            findings: [
              {
                name: "Email address disclosure",
                severity: "low",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should not find emails when no content-type header", async () => {
    const request = createMockRequest({
      id: "4",
      host: "targetsite.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "4",
      code: 404,
      headers: {},
      body: "Contact us at admin@targetsite.com for support",
    });

    const executionHistory = await runCheck(
      emailDisclosureScan,
      [{ request, response }],
      {
        sendHandler: () => Promise.resolve({ request, response }),
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    // Check still runs (when: () => true) but produces no findings (no content-type)
    expect(executionHistory).toHaveLength(1);
    const findings = executionHistory[0]?.steps.flatMap((s: any) => s.findings) ?? [];
    expect(findings).toEqual([]);
  });

  it("should not trigger on content without emails", async () => {
    const request = createMockRequest({
      id: "5",
      host: "targetsite.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "5",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "Welcome to our website",
    });

    const executionHistory = await runCheck(
      emailDisclosureScan,
      [{ request, response }],
      {
        sendHandler: () => Promise.resolve({ request, response }),
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "email-disclosure",
        targetRequestId: "5",
        status: "completed",
      },
    ]);

    const allFindings =
      executionHistory[0]?.steps.flatMap((step: any) => step.findings) ?? [];
    expect(allFindings).toEqual([]);
  });
});
