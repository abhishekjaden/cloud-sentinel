/**
 * Cognito hosted-UI login via authorization code + PKCE.
 *
 * Implicit grant is deprecated (tokens leak through URL fragments, history and
 * referrers), so we use the code flow with a PKCE verifier: the browser holds a
 * one-time secret, sends only its hash to Cognito, and proves possession when
 * exchanging the code for tokens.
 */
const DOMAIN = "https://cloudsentinel-soc.auth.us-east-1.amazoncognito.com";
const CLIENT_ID = "3i0gv6cm27of4hancq8fjs551t";
const REDIRECT_URI = window.location.origin;
const SCOPES = "openid email profile";

const TOKEN_KEY = "cs_access_token";
const VERIFIER_KEY = "cs_pkce_verifier";

function randomString(len = 64): string {
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => ("0" + b.toString(16)).slice(-2)).join("").slice(0, len);
}

async function sha256Base64Url(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  const bytes = new Uint8Array(digest);
  let bin = "";
  bytes.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function getToken(): string | null {
  return sessionStorage.getItem(TOKEN_KEY);
}

export function isAuthenticated(): boolean {
  const t = getToken();
  if (!t) return false;
  try {
    const payload = JSON.parse(atob(t.split(".")[1]));
    return payload.exp * 1000 > Date.now();
  } catch {
    return false;
  }
}

/** Send the user to the Cognito hosted login page. */
export async function login(): Promise<void> {
  const verifier = randomString(64);
  sessionStorage.setItem(VERIFIER_KEY, verifier);
  const challenge = await sha256Base64Url(verifier);
  const url =
    `${DOMAIN}/oauth2/authorize?response_type=code&client_id=${CLIENT_ID}` +
    `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
    `&scope=${encodeURIComponent(SCOPES)}` +
    `&code_challenge=${challenge}&code_challenge_method=S256`;
  window.location.href = url;
}

/** If we came back from Cognito with ?code=..., swap it for tokens. */
export async function handleRedirect(): Promise<boolean> {
  const params = new URLSearchParams(window.location.search);
  const code = params.get("code");
  if (!code) return false;

  const verifier = sessionStorage.getItem(VERIFIER_KEY);
  if (!verifier) return false;

  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: CLIENT_ID,
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: verifier,
  });

  const res = await fetch(`${DOMAIN}/oauth2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  if (!res.ok) return false;

  const tokens = await res.json();
  sessionStorage.setItem(TOKEN_KEY, tokens.access_token);
  sessionStorage.removeItem(VERIFIER_KEY);
  window.history.replaceState({}, "", REDIRECT_URI); // strip ?code from the URL
  return true;
}

export function logout(): void {
  sessionStorage.removeItem(TOKEN_KEY);
  window.location.href =
    `${DOMAIN}/logout?client_id=${CLIENT_ID}&logout_uri=${encodeURIComponent(REDIRECT_URI)}`;
}
