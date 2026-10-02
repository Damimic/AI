import { basicAuthHeader, clearCredentials, getStoredCredentials } from "./auth";

export class UnauthorizedError extends Error {
  constructor() {
    super("unauthorized");
  }
}

export class APIError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export interface Finding {
  host: string;
  package: string;
  version: string;
  cve_id: string;
  severity: string;
  fixed_version?: string;
  status?: string;
  reported_at: string;
}

export interface FindingsResponse {
  findings: Finding[];
  hostnames: string[];
}

export interface FindingsFilter {
  host?: string;
  severity?: string;
}

/**
 * Verifies a credential actually works by making a real request against
 * the dashboard API — this is the login flow's only source of truth.
 * There's no separate "check credentials" endpoint; a 200 here just means
 * the same request a later page load would make also worked.
 */
export async function verifyCredentials(
  username: string,
  password: string,
): Promise<boolean> {
  const res = await fetch("/api/findings", {
    headers: { Authorization: basicAuthHeader({ username, password }) },
  });
  return res.ok;
}

export async function fetchFindings(
  filter: FindingsFilter = {},
): Promise<FindingsResponse> {
  const credentials = getStoredCredentials();
  if (!credentials) throw new UnauthorizedError();

  const params = new URLSearchParams();
  if (filter.host) params.set("host", filter.host);
  if (filter.severity) params.set("severity", filter.severity);
  const query = params.toString();

  const res = await fetch(`/api/findings${query ? `?${query}` : ""}`, {
    headers: { Authorization: basicAuthHeader(credentials) },
  });

  if (res.status === 401) {
    clearCredentials();
    throw new UnauthorizedError();
  }
  if (!res.ok) {
    throw new APIError(res.status, `fetching findings: ${res.status}`);
  }
  return res.json();
}

export interface WaitlistResponse {
  status: "success" | "duplicate" | "invalid";
  message?: string;
}

export async function joinWaitlist(email: string): Promise<WaitlistResponse> {
  const res = await fetch("/waitlist", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
  });
  const body = (await res.json()) as WaitlistResponse;
  if (res.status >= 500) {
    throw new APIError(res.status, body.message ?? "something went wrong");
  }
  return body;
}
