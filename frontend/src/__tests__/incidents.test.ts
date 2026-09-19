/**
 * Tests for the correlated-incidents view.
 *
 * The panel is where an analyst decides what to look at first, so what it
 * claims must be exactly what the data says: stages in the order the backend
 * computed, "multi-stage" only where the attack spans several stages, and a
 * sample label only where the incident came from GuardDuty test data.
 *
 * Rendered with react-dom directly rather than a testing library, so the test
 * adds no dependency to the project.
 */
import { describe, test, expect, afterEach } from "vitest";
import { act, createElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { IncidentsPanel } from "../components/IncidentsPanel";
import { describeSpan, formatDuration, severityBucket, stageLabel } from "../incidents";
import type { Incident, IncidentsResponse } from "../types";

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

// ------------------------------------------------------------------ helpers
describe("severityBucket", () => {
  // Pinned to the normalizer's boundaries: an incident must not read as less
  // severe than the worst finding it contains.
  test.each([
    [100, "CRITICAL"], [90, "CRITICAL"], [89, "HIGH"], [70, "HIGH"],
    [69, "MEDIUM"], [40, "MEDIUM"], [39, "LOW"], [1, "LOW"], [0, "INFO"],
  ])("%i is %s", (score, bucket) => {
    expect(severityBucket(score)).toBe(bucket);
  });
});

describe("formatDuration", () => {
  test.each([
    [37, "37s"], [60, "1m"], [250, "4m 10s"], [3600, "1h"],
    [7500, "2h 5m"], [86400, "1d"], [90000, "1d 1h"],
  ])("%i seconds reads as %s", (seconds, text) => {
    expect(formatDuration(seconds)).toBe(text);
  });

  test("a value that is not a duration renders as a dash, not NaN", () => {
    expect(formatDuration(Number.NaN)).toBe("—");
    expect(formatDuration(-5)).toBe("—");
  });
});

describe("describeSpan", () => {
  test("a single finding claims no span", () => {
    expect(describeSpan(1, 0)).toBe("1 finding");
  });

  test("findings raised in the same instant do not read as '0s'", () => {
    // Seen live: a sample batch's two findings shared a timestamp.
    expect(describeSpan(2, 0)).toBe("2 findings within a second");
  });

  test("a real span is stated", () => {
    expect(describeSpan(3, 37)).toBe("3 findings over 37s");
  });
});

test("stage names read as words", () => {
  expect(stageLabel("command-and-control")).toBe("command and control");
});

// ---------------------------------------------------------------- rendering
const roots: Root[] = [];

function render(data: IncidentsResponse | null, error: string | null = null): HTMLElement {
  const host = document.createElement("div");
  document.body.appendChild(host);
  const root = createRoot(host);
  roots.push(root);
  act(() => root.render(createElement(IncidentsPanel, { data, error })));
  return host;
}

afterEach(() => {
  roots.splice(0).forEach((r) => act(() => r.unmount()));
  document.body.innerHTML = "";
});

function incident(overrides: Partial<Incident>): Incident {
  return {
    incident_id: "i1", account_id: "111122223333", resource: "i-0abc",
    first_seen: "2026-07-19T13:47:58+00:00", last_seen: "2026-07-19T13:48:35+00:00",
    duration_seconds: 37, finding_count: 3, max_severity: 90,
    attack_stages: ["initial-access", "command-and-control", "impact"],
    multi_stage: true, finding_types: [], status: "open", sample: false,
    ...overrides,
  };
}

function response(incidents: Incident[]): IncidentsResponse {
  return {
    count: incidents.length,
    multi_stage: incidents.filter((i) => i.multi_stage).length,
    incidents,
  };
}

const cards = (host: HTMLElement) => [...host.querySelectorAll(".incident-card")];

describe("IncidentsPanel", () => {
  test("stages appear in the order the correlator computed", () => {
    const host = render(response([incident({})]));
    const stages = [...host.querySelectorAll(".stage-chain .stage-pill")].map((s) => s.textContent);
    expect(stages).toEqual(["initial access", "command and control", "impact"]);
  });

  test("only incidents spanning several stages are marked multi-stage", () => {
    const host = render(response([
      incident({ incident_id: "a" }),
      incident({ incident_id: "b", attack_stages: ["impact"], multi_stage: false, finding_count: 1 }),
    ]));
    const [multi, single] = cards(host);
    expect(multi.querySelector(".tag-multi")).not.toBeNull();
    expect(single.querySelector(".tag-multi")).toBeNull();
  });

  test("sample-derived incidents are labelled, and still shown", () => {
    const host = render(response([
      incident({ incident_id: "real" }),
      incident({ incident_id: "sample", resource: "i-99999999", sample: true }),
    ]));
    const [real, sample] = cards(host);
    expect(cards(host)).toHaveLength(2);
    expect(real.querySelector(".tag-sample")).toBeNull();
    expect(sample.querySelector(".tag-sample")).not.toBeNull();
    expect(host.querySelector(".status-sample .summary-count")?.textContent).toBe("1");
  });

  test("no sample summary appears when nothing came from samples", () => {
    const host = render(response([incident({})]));
    expect(host.querySelector(".status-sample")).toBeNull();
  });

  test("a single-finding incident does not claim a duration", () => {
    const host = render(response([incident({
      finding_count: 1, duration_seconds: 0, attack_stages: ["impact"], multi_stage: false,
    })]));
    const meta = host.querySelector(".incident-meta")?.textContent ?? "";
    expect(meta).toContain("1 finding");
    expect(meta).not.toContain("over");
  });

  test("a multi-finding incident states its span", () => {
    const host = render(response([incident({})]));
    expect(host.querySelector(".incident-meta")?.textContent).toContain("3 findings over 37s");
  });

  test("an empty table says so rather than rendering nothing", () => {
    const host = render(response([]));
    expect(host.textContent).toContain("No correlated incidents.");
  });

  test("a failed request shows its own error instead of stale data", () => {
    const host = render(response([incident({})]), "Request failed with status code 500");
    expect(host.textContent).toContain("Could not load incidents");
    expect(cards(host)).toHaveLength(0);
  });

  test("before the first response it shows a loading state", () => {
    expect(render(null).textContent).toContain("Loading incidents");
  });
});
