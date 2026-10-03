/**
 * Display logic for the prediction panel, kept apart from the component so it
 * can be tested without rendering.
 *
 * Two models score every flow. The binary detector's answer is the verdict;
 * the eight-class model's answer is the attack family, a second opinion with
 * uneven reliability (the model card gives Bot a precision of 0.648). The two
 * can disagree, and each of the four combinations is said plainly rather than
 * reconciled into one tidy answer the data does not support.
 */
import type { PredictResponse } from "./types";

export function percent(p: number): string {
  return `${(p * 100).toFixed(1)}%`;
}

/** One line on the family, read beside the verdict. */
export function describeFamily(r: PredictResponse): string {
  const benign = r.attack_family === "BENIGN";
  const p = percent(r.family_probability);
  if (r.prediction === "ATTACK") {
    return benign
      ? `Family undetermined: the family classifier rates this flow benign (${p})`
      : `Most likely family: ${r.attack_family} (${p})`;
  }
  return benign
    ? `Family classifier agrees: benign (${p})`
    : `Family classifier disagrees: ${r.attack_family} (${p})`;
}

/**
 * The leading families by probability, so the margin behind the family is
 * visible: a 0.51 call over a 0.49 runner-up should not read like a 0.99 one.
 */
export function topFamilies(
  probabilities: Record<string, number>, n = 3,
): Array<[string, number]> {
  return Object.entries(probabilities)
    .sort((a, b) => b[1] - a[1])
    .slice(0, n);
}
