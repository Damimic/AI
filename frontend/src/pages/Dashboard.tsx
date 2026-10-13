import { ExternalLink, LogOut, ShieldCheck } from "lucide-react";
import { useEffect, useReducer, useState } from "react";
import { useNavigate } from "react-router-dom";
import { fetchFindings, UnauthorizedError, type Finding } from "../lib/api";
import { clearCredentials } from "../lib/auth";
import { SeverityBadge, StatusBadge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { Select } from "../components/ui/Input";

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

interface FetchState {
  loading: boolean;
  error: string | null;
  findings: Finding[];
  hostnames: string[];
}

type FetchAction =
  | { type: "started" }
  | { type: "succeeded"; findings: Finding[]; hostnames: string[] }
  | { type: "failed"; message: string };

// A single dispatch per transition, not several setState calls in a row —
// each fetch's start/success/failure is one atomic state change, not three
// independently-settable fields that could briefly disagree with each
// other (e.g. "not loading" with stale findings from the previous filter).
function fetchReducer(state: FetchState, action: FetchAction): FetchState {
  switch (action.type) {
    case "started":
      return { ...state, loading: true, error: null };
    case "succeeded":
      return { loading: false, error: null, findings: action.findings, hostnames: action.hostnames };
    case "failed":
      return { ...state, loading: false, error: action.message };
  }
}

export function Dashboard() {
  const navigate = useNavigate();
  const [host, setHost] = useState("");
  const [severity, setSeverity] = useState("");
  const [{ loading, error, findings, hostnames }, dispatch] = useReducer(fetchReducer, {
    loading: true,
    error: null,
    findings: [],
    hostnames: [],
  });

  useEffect(() => {
    let cancelled = false;
    dispatch({ type: "started" });
    fetchFindings({ host, severity })
      .then((res) => {
        if (cancelled) return;
        dispatch({ type: "succeeded", findings: res.findings, hostnames: res.hostnames });
      })
      .catch((err) => {
        if (cancelled) return;
        if (err instanceof UnauthorizedError) {
          navigate("/login");
          return;
        }
        dispatch({ type: "failed", message: "Couldn't load findings — check the backend is running." });
      });
    return () => {
      cancelled = true;
    };
  }, [host, severity, navigate]);

  function handleLogout() {
    clearCredentials();
    navigate("/login");
  }

  const counts = SEVERITIES.map((s) => ({
    severity: s,
    count: findings.filter((f) => f.severity === s).length,
  }));

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950">
      <header className="border-b border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
          <div className="flex items-center gap-2">
            <div className="flex size-7 items-center justify-center rounded-lg bg-brand-600 text-white">
              <ShieldCheck className="size-4" />
            </div>
            <span className="text-base font-semibold text-slate-900 dark:text-white">Kepler</span>
          </div>
          <Button variant="ghost" onClick={handleLogout}>
            <LogOut className="size-4" />
            Sign out
          </Button>
        </div>
      </header>

      <main className="mx-auto max-w-7xl px-6 py-8">
        <div className="mb-6 flex items-end justify-between">
          <div>
            <h1 className="text-xl font-semibold text-slate-900 dark:text-white">Findings</h1>
            <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
              {loading ? "Loading…" : `${findings.length} finding${findings.length === 1 ? "" : "s"}`}
            </p>
          </div>
          <div className="flex gap-2">
            <Select value={host} onChange={(e) => setHost(e.target.value)} aria-label="Filter by host">
              <option value="">All hosts</option>
              {hostnames.map((h) => (
                <option key={h} value={h}>
                  {h}
                </option>
              ))}
            </Select>
            <Select value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Filter by severity">
              <option value="">All severities</option>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </Select>
          </div>
        </div>

        <div className="mb-6 grid grid-cols-4 gap-3">
          {counts.map(({ severity: s, count }) => (
            <button
              key={s}
              onClick={() => setSeverity(severity === s ? "" : s)}
              className="rounded-xl bg-white p-4 text-left shadow-sm ring-1 ring-slate-200 transition-shadow hover:shadow-md dark:bg-slate-900 dark:ring-slate-800"
            >
              <div className="text-2xl font-semibold text-slate-900 dark:text-white">{count}</div>
              <div className="mt-1">
                <SeverityBadge severity={s} />
              </div>
            </button>
          ))}
        </div>

        {error && (
          <div className="mb-4 rounded-lg bg-red-50 px-4 py-3 text-sm text-red-700 ring-1 ring-inset ring-red-600/20 dark:bg-red-950/50 dark:text-red-400 dark:ring-red-400/30">
            {error}
          </div>
        )}

        <div className="overflow-x-auto rounded-xl bg-white shadow-sm ring-1 ring-slate-200 dark:bg-slate-900 dark:ring-slate-800">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-200 text-xs font-medium uppercase tracking-wide text-slate-500 dark:border-slate-800 dark:text-slate-400">
                <th className="px-4 py-3">Host</th>
                <th className="px-4 py-3">Package</th>
                <th className="px-4 py-3">Version</th>
                <th className="px-4 py-3">CVE</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Fixed version</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Reported</th>
              </tr>
            </thead>
            <tbody>
              {!loading && findings.length === 0 && (
                <tr>
                  <td colSpan={8} className="px-4 py-12 text-center text-slate-400 dark:text-slate-500">
                    No findings match this filter.
                  </td>
                </tr>
              )}
              {findings.map((f, i) => (
                <tr
                  key={`${f.host}-${f.cve_id}-${i}`}
                  className="border-b border-slate-100 last:border-0 hover:bg-slate-50 dark:border-slate-800/60 dark:hover:bg-slate-800/40"
                >
                  <td className="px-4 py-3 font-medium text-slate-900 dark:text-white">{f.host}</td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-600 dark:text-slate-400">{f.package}</td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-600 dark:text-slate-400">{f.version}</td>
                  <td className="px-4 py-3">
                    <a
                      href={`https://nvd.nist.gov/vuln/detail/${f.cve_id}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 font-mono text-xs text-brand-600 hover:underline dark:text-brand-400"
                    >
                      {f.cve_id}
                      <ExternalLink className="size-3" />
                    </a>
                  </td>
                  <td className="px-4 py-3">
                    <SeverityBadge severity={f.severity} />
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-600 dark:text-slate-400">
                    {f.fixed_version ?? "—"}
                  </td>
                  <td className="px-4 py-3">
                    <StatusBadge status={f.status} />
                  </td>
                  <td className="px-4 py-3 text-xs text-slate-500 dark:text-slate-400">
                    {new Date(f.reported_at).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </main>
    </div>
  );
}
