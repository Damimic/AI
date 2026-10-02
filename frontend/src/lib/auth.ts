// The dashboard's auth is still plain HTTP Basic Auth server-side (see
// web/internal/auth — one shared operator credential, deliberate for v1,
// not worth rebuilding into sessions/JWTs for a single-operator model).
// What changes here is presentation: instead of the browser's native
// Basic Auth popup, this app collects the credential through its own
// styled login form and attaches it to every API call itself.
//
// Stored in sessionStorage, not localStorage — cleared when the tab
// closes rather than persisting indefinitely on a shared machine. This is
// a real tradeoff (re-login every new tab/session) made deliberately in
// favor of not leaving a working credential sitting in storage
// indefinitely; revisit if that friction becomes a real complaint.
const STORAGE_KEY = "kepler.dashboard.credentials";

export interface Credentials {
  username: string;
  password: string;
}

export function getStoredCredentials(): Credentials | null {
  const raw = sessionStorage.getItem(STORAGE_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as Credentials;
  } catch {
    sessionStorage.removeItem(STORAGE_KEY);
    return null;
  }
}

export function storeCredentials(credentials: Credentials): void {
  sessionStorage.setItem(STORAGE_KEY, JSON.stringify(credentials));
}

export function clearCredentials(): void {
  sessionStorage.removeItem(STORAGE_KEY);
}

export function basicAuthHeader(credentials: Credentials): string {
  return "Basic " + btoa(`${credentials.username}:${credentials.password}`);
}
