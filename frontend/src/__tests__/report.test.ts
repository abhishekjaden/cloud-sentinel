/**
 * Tests for the incident report download.
 *
 * The report route is authenticated, so the panel fetches the PDF with the
 * operator's token and hands the bytes to the browser's download flow rather
 * than linking to the URL. What is pinned: the click asks for the right
 * incident, the file gets the name the API would give it, a failure is shown
 * on the card it belongs to, and the button is busy only while its own fetch
 * is in flight.
 *
 * Rendered with react-dom directly rather than a testing library, so the test
 * adds no dependency to the project.
 */
import { describe, test, expect, afterEach, beforeEach, vi } from "vitest";
import { act, createElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { IncidentsPanel } from "../components/IncidentsPanel";
import { reportFilename } from "../incidents";
import type { Incident, IncidentsResponse } from "../types";

vi.mock("../api", () => ({ getIncidentReport: vi.fn() }));
import { getIncidentReport } from "../api";
const fetchReport = vi.mocked(getIncidentReport);

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

describe("reportFilename", () => {
  test("is built from the incident ID, shortened and made of safe characters", () => {
    expect(reportFilename("3f9c2a7d1e4b5c6a7b8c9d0e1f2a3b4c")).toBe("cloudsentinel-incident-3f9c2a7d1e4b.pdf");
    expect(reportFilename('ab"c/d')).toBe("cloudsentinel-incident-abcd.pdf");
  });
});

// ---------------------------------------------------------------- rendering
const roots: Root[] = [];
const downloads: Array<{ href: string; download: string }> = [];

function render(data: IncidentsResponse): HTMLElement {
  const host = document.createElement("div");
  document.body.appendChild(host);
  const root = createRoot(host);
  roots.push(root);
  act(() => root.render(createElement(IncidentsPanel, { data, error: null })));
  return host;
}

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
  return { count: incidents.length, multi_stage: incidents.length, incidents };
}

const buttons = (host: HTMLElement) => [...host.querySelectorAll<HTMLButtonElement>(".report-link")];

async function click(button: HTMLButtonElement) {
  await act(async () => { button.click(); });
}

beforeEach(() => {
  fetchReport.mockReset();
  downloads.length = 0;
  // jsdom has neither object URLs nor navigation; the download is observed
  // through the anchor the panel creates and clicks.
  URL.createObjectURL = vi.fn(() => "blob:report");
  URL.revokeObjectURL = vi.fn();
  HTMLAnchorElement.prototype.click = function () {
    downloads.push({ href: this.href, download: this.download });
  };
});

afterEach(() => {
  roots.splice(0).forEach((r) => act(() => r.unmount()));
  document.body.innerHTML = "";
});

describe("report download", () => {
  test("every incident offers a report, and the click asks for that incident", async () => {
    fetchReport.mockResolvedValue(new Blob(["%PDF-1.4"], { type: "application/pdf" }));
    const host = render(response([incident({ incident_id: "first" }), incident({ incident_id: "second" })]));
    const [, second] = buttons(host);
    expect(buttons(host)).toHaveLength(2);
    expect(second.textContent).toBe("Report (PDF)");

    await click(second);

    expect(fetchReport).toHaveBeenCalledTimes(1);
    expect(fetchReport).toHaveBeenCalledWith("second");
    expect(downloads).toEqual([{ href: "blob:report", download: "cloudsentinel-incident-second.pdf" }]);
    expect(URL.revokeObjectURL).toHaveBeenCalledWith("blob:report");
  });

  test("while a report is being fetched its button is busy and the others are not", async () => {
    let finish!: (blob: Blob) => void;
    fetchReport.mockReturnValue(new Promise<Blob>((resolve) => { finish = resolve; }));
    const host = render(response([incident({ incident_id: "a" }), incident({ incident_id: "b" })]));
    const [a, b] = buttons(host);

    await click(a);
    expect(a.disabled).toBe(true);
    expect(a.textContent).toBe("Preparing report…");
    expect(b.disabled).toBe(false);

    await act(async () => { finish(new Blob()); });
    expect(a.disabled).toBe(false);
    expect(a.textContent).toBe("Report (PDF)");
  });

  test("a failed fetch is shown on the card it belongs to, and nothing is downloaded", async () => {
    fetchReport.mockRejectedValue(new Error("Request failed with status code 500"));
    const host = render(response([incident({ incident_id: "a" }), incident({ incident_id: "b" })]));
    const [a, b] = buttons(host);

    await click(a);

    const [cardA, cardB] = [...host.querySelectorAll(".incident-card")];
    expect(cardA.textContent).toContain("Report failed: Request failed with status code 500");
    expect(cardB.textContent).not.toContain("Report failed");
    expect(downloads).toEqual([]);
    expect(b.disabled).toBe(false);
  });
});
