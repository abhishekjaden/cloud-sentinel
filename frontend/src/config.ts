// Runtime config: fetch API URL from /config.json at startup so the built
// artifact isn't coupled to a specific backend URL. Falls back to the
// build-time env var, then localhost.
let cachedBaseUrl: string | null = null;

export async function loadApiBaseUrl(): Promise<string> {
  if (cachedBaseUrl) return cachedBaseUrl;
  try {
    const res = await fetch("/config.json", { cache: "no-store" });
    if (res.ok) {
      const cfg = await res.json();
      if (cfg.apiUrl) {
        cachedBaseUrl = cfg.apiUrl as string;
        return cachedBaseUrl;
      }
    }
  } catch {
    // fall through to env / localhost
  }
  cachedBaseUrl =
    (import.meta.env.VITE_API_URL as string) || "http://localhost:8000";
  return cachedBaseUrl;
}
