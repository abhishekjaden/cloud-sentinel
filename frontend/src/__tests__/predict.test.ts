/**
 * Tests for the prediction panel's display logic.
 *
 * Two models answer every scored flow and they can disagree. What the panel
 * says in each of the four combinations is pinned here, because the easy
 * mistake — showing the family only when it agrees with the verdict — would
 * hide exactly the cases an analyst should see.
 *
 * Rendered with react-dom directly rather than a testing library, so the test
 * adds no dependency to the project.
 */
import { describe, test, expect, afterEach } from "vitest";
import { act, createElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { PredictResult } from "../components/PredictPanel";
import { describeFamily, percent, topFamilies } from "../predict";
import type { PredictResponse } from "../types";

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

function response(over: Partial<PredictResponse> = {}): PredictResponse {
  return {
    attack_probability: 0.9731,
    prediction: "ATTACK",
    threshold: 0.5,
    attack_family: "DoS",
    family_probability: 0.9412,
    family_probabilities: {
      BENIGN: 0.0101, Bot: 0.0012, BruteForce: 0.0008, DDoS: 0.0391,
      DoS: 0.9412, Infiltration: 0.0001, PortScan: 0.0063, WebAttack: 0.0012,
    },
    ...over,
  };
}

// ------------------------------------------------------------------ helpers
describe("describeFamily", () => {
  test("an attack with a named family says the family and its probability", () => {
    expect(describeFamily(response())).toBe("Most likely family: DoS (94.1%)");
  });

  test("an attack the family model calls benign is undetermined, not relabelled", () => {
    expect(describeFamily(response({ attack_family: "BENIGN", family_probability: 0.62 })))
      .toBe("Family undetermined: the family classifier rates this flow benign (62.0%)");
  });

  test("a benign verdict the family model agrees with says so", () => {
    expect(describeFamily(response({
      prediction: "BENIGN", attack_probability: 0.03, attack_family: "BENIGN", family_probability: 0.998,
    }))).toBe("Family classifier agrees: benign (99.8%)");
  });

  test("a benign verdict the family model disputes shows the dispute", () => {
    expect(describeFamily(response({
      prediction: "BENIGN", attack_probability: 0.21, attack_family: "PortScan", family_probability: 0.55,
    }))).toBe("Family classifier disagrees: PortScan (55.0%)");
  });
});

describe("topFamilies", () => {
  test("returns the leading classes by probability, highest first", () => {
    expect(topFamilies(response().family_probabilities)).toEqual([
      ["DoS", 0.9412], ["DDoS", 0.0391], ["BENIGN", 0.0101],
    ]);
  });

  test("takes as many as asked for", () => {
    expect(topFamilies(response().family_probabilities, 1)).toEqual([["DoS", 0.9412]]);
  });
});

describe("percent", () => {
  test("shows one decimal place", () => {
    expect(percent(0.9412)).toBe("94.1%");
    expect(percent(1)).toBe("100.0%");
  });
});

// ---------------------------------------------------------------- rendering
const roots: Root[] = [];

function render(result: PredictResponse): HTMLElement {
  const host = document.createElement("div");
  const root = createRoot(host);
  roots.push(root);
  act(() => root.render(createElement(PredictResult, { result })));
  return host;
}

afterEach(() => {
  roots.splice(0).forEach((r) => act(() => r.unmount()));
});

describe("PredictResult", () => {
  test("shows the verdict, the family and the margin behind it", () => {
    const host = render(response());
    expect(host.querySelector(".predict-result")?.classList.contains("attack")).toBe(true);
    expect(host.querySelector(".predict-label")?.textContent).toBe("ATTACK");
    expect(host.querySelector(".predict-prob")?.textContent).toBe("97.31% attack probability");
    expect(host.querySelector(".predict-family")?.textContent).toBe("Most likely family: DoS (94.1%)");
    const margin = [...host.querySelectorAll(".predict-margin-item")].map((e) => e.textContent);
    expect(margin).toEqual(["DoS 94.1%", "DDoS 3.9%", "BENIGN 1.0%"]);
  });

  test("a benign verdict is styled benign whatever the family model says", () => {
    const host = render(response({ prediction: "BENIGN", attack_probability: 0.2, attack_family: "PortScan" }));
    expect(host.querySelector(".predict-result")?.classList.contains("benign")).toBe(true);
    expect(host.querySelector(".predict-family")?.textContent).toContain("disagrees: PortScan");
  });
});
