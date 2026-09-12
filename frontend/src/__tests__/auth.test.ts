/**
 * Tests for the PKCE authorization-code flow.
 *
 * This module is the browser half of the security boundary: it generates the
 * one-time verifier, proves possession when exchanging the code, and decides
 * whether the session is still valid. A defect here is a security defect, not
 * a cosmetic one, so the properties PKCE depends on are asserted directly.
 */
import { describe, test, expect, beforeEach, vi, afterEach } from "vitest";

const DOMAIN = "https://cloudsentinel-soc.auth.us-east-1.amazoncognito.com";
const VERIFIER_KEY = "cs_pkce_verifier";
const TOKEN_KEY = "cs_access_token";

/** Build a JWT whose payload expires at the given offset from now. */
function jwt(expOffsetSeconds: number, extra: Record<string, unknown> = {}): string {
  const payload = { sub: "operator-1", exp: Math.floor(Date.now() / 1000) + expOffsetSeconds, ...extra };
  const b64 = btoa(JSON.stringify(payload))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `header.${b64}.signature`;
}

/**
 * jsdom refuses to navigate, so assigning window.location.href is a no-op and
 * the redirect cannot be inspected. Replacing location with a plain object
 * captures what the module tried to navigate to.
 */
let navigatedTo = "";

beforeEach(() => {
  sessionStorage.clear();
  vi.restoreAllMocks();
  navigatedTo = "";
  Object.defineProperty(window, "location", {
    configurable: true,
    value: {
      origin: "http://localhost:3000",
      search: "",
      get href() {
        return navigatedTo;
      },
      set href(v: string) {
        navigatedTo = v;
      },
    },
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

// ------------------------------------------------------------------ session
describe("session state", () => {
  test("no token means not authenticated", async () => {
    const { getToken, isAuthenticated } = await import("../auth");
    expect(getToken()).toBeNull();
    expect(isAuthenticated()).toBe(false);
  });

  test("a malformed token is rejected rather than throwing", async () => {
    const { isAuthenticated } = await import("../auth");
    sessionStorage.setItem(TOKEN_KEY, "not-a-jwt");
    expect(isAuthenticated()).toBe(false);
  });

  test("an expired token is rejected", async () => {
    const { isAuthenticated } = await import("../auth");
    sessionStorage.setItem(TOKEN_KEY, jwt(-3600));
    expect(isAuthenticated()).toBe(false);
  });

  test("a valid unexpired token is accepted", async () => {
    const { isAuthenticated } = await import("../auth");
    sessionStorage.setItem(TOKEN_KEY, jwt(3600));
    expect(isAuthenticated()).toBe(true);
  });

  test("a base64url payload containing - or _ is still decoded", async () => {
    // JWT payloads are base64url, which uses - and _ in place of + and /.
    // atob() accepts only standard base64, so a payload containing either
    // character throws and the session is wrongly reported as logged out.
    const { isAuthenticated } = await import("../auth");
    let token = "";
    for (let i = 0; i < 400 && !token; i++) {
      const candidate = jwt(3600, { nonce: `padding-${i}-\u00ff\u00fe` });
      const payload = candidate.split(".")[1];
      if (payload.includes("-") || payload.includes("_")) token = candidate;
    }
    expect(token, "expected to construct a base64url payload").not.toBe("");
    sessionStorage.setItem(TOKEN_KEY, token);
    expect(isAuthenticated()).toBe(true);
  });

  test("logout clears the stored token", async () => {
    const { logout } = await import("../auth");
    sessionStorage.setItem(TOKEN_KEY, jwt(3600));
    logout();
    expect(sessionStorage.getItem(TOKEN_KEY)).toBeNull();
  });
});

// --------------------------------------------------------------------- PKCE
describe("PKCE login", () => {
  test("stores a verifier and redirects to the hosted UI with an S256 challenge", async () => {
    const { login } = await import("../auth");
    await login();

    const verifier = sessionStorage.getItem(VERIFIER_KEY);
    expect(verifier).toBeTruthy();
    expect(window.location.href).toContain(`${DOMAIN}/oauth2/authorize`);
    expect(window.location.href).toContain("response_type=code");
    expect(window.location.href).toContain("code_challenge_method=S256");
    // The verifier itself must never appear in the redirect; only its hash.
    expect(window.location.href).not.toContain(verifier as string);
  });

  test("the verifier meets RFC 7636 length requirements", async () => {
    const { login } = await import("../auth");
    await login();
    const verifier = sessionStorage.getItem(VERIFIER_KEY) as string;
    expect(verifier.length).toBeGreaterThanOrEqual(43);
    expect(verifier.length).toBeLessThanOrEqual(128);
    expect(verifier).toMatch(/^[A-Za-z0-9\-._~]+$/);
  });

  test("a fresh verifier is generated on every login", async () => {
    // Reusing a verifier would defeat the mechanism entirely.
    const { login } = await import("../auth");
    await login();
    const first = sessionStorage.getItem(VERIFIER_KEY);
    await login();
    const second = sessionStorage.getItem(VERIFIER_KEY);
    expect(second).not.toBe(first);
  });

  test("the challenge is the base64url SHA-256 of the verifier", async () => {
    const { login } = await import("../auth");
    await login();
    const verifier = sessionStorage.getItem(VERIFIER_KEY) as string;

    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
    let bin = "";
    new Uint8Array(digest).forEach((b) => (bin += String.fromCharCode(b)));
    const expected = btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

    expect(window.location.href).toContain(`code_challenge=${expected}`);
    // Padding must be stripped: '=' would be percent-encoded and rejected.
    expect(expected).not.toContain("=");
  });
});

// ----------------------------------------------------------------- redirect
describe("authorization code exchange", () => {
  test("does nothing when there is no code in the query string", async () => {
    const { handleRedirect } = await import("../auth");
    expect(await handleRedirect()).toBe(false);
  });

  test("refuses to exchange a code when no verifier was stored", async () => {
    // Without the verifier this browser never initiated the login, so a code
    // appearing in the URL did not originate here.
    const { handleRedirect } = await import("../auth");
    window.location.search = "?code=injected-by-someone-else";
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    expect(await handleRedirect()).toBe(false);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  test("sends the verifier and stores the returned token", async () => {
    const { handleRedirect } = await import("../auth");
    sessionStorage.setItem(VERIFIER_KEY, "stored-verifier");
    window.location.search = "?code=good-code";

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ access_token: jwt(3600) }),
    });
    vi.stubGlobal("fetch", fetchMock);

    expect(await handleRedirect()).toBe(true);

    const body = (fetchMock.mock.calls[0][1] as { body: URLSearchParams }).body.toString();
    expect(body).toContain("grant_type=authorization_code");
    expect(body).toContain("code_verifier=stored-verifier");
    expect(sessionStorage.getItem(TOKEN_KEY)).toBeTruthy();
  });

  test("the spent verifier is discarded after a successful exchange", async () => {
    const { handleRedirect } = await import("../auth");
    sessionStorage.setItem(VERIFIER_KEY, "stored-verifier");
    window.location.search = "?code=good-code";
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true, json: async () => ({ access_token: jwt(3600) }),
    }));

    await handleRedirect();
    expect(sessionStorage.getItem(VERIFIER_KEY)).toBeNull();
  });

  test("a rejected exchange stores no token", async () => {
    const { handleRedirect } = await import("../auth");
    sessionStorage.setItem(VERIFIER_KEY, "stored-verifier");
    window.location.search = "?code=bad-code";
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 400 }));

    expect(await handleRedirect()).toBe(false);
    expect(sessionStorage.getItem(TOKEN_KEY)).toBeNull();
  });
});
