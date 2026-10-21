import { CheckCircle2, Lock, ScanSearch, ShieldCheck } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { joinWaitlist } from "../lib/api";
import { AuroraBackground } from "../components/AuroraBackground";
import { TiltPreviewCard } from "../components/TiltPreviewCard";
import { SeverityBadge, StatusBadge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { Input } from "../components/ui/Input";

// Illustrative only — the landing page is public and unauthenticated by
// design, so it never queries real findings. Labeled as an example in
// the UI itself, same honesty bar as the chat widget's "simulated
// preview" badge.
const PREVIEW_FINDINGS = [
  { host: "web-prod-01", package: "openssl", cveId: "CVE-2023-0286", severity: "CRITICAL", status: "fixed" },
  { host: "db-prod-02", package: "libssl3", cveId: "CVE-2022-3786", severity: "HIGH", status: "affected" },
  { host: "app-prod-03", package: "curl", cveId: "CVE-2023-27536", severity: "MEDIUM", status: "fixed" },
];

const FEATURES = [
  {
    icon: ScanSearch,
    title: "Real CVE matching",
    body: "Every finding is matched against the actual Debian and Ubuntu security trackers — not a generic version check that flags backported fixes as still vulnerable.",
  },
  {
    icon: ShieldCheck,
    title: "Know what to fix first",
    body: "Each finding carries its real remediation status: a patch available now, versus no fix coming and a compensating control needed instead.",
  },
  {
    icon: Lock,
    title: "Built read-only, by design",
    body: "The agent only ever reads. No elevated privileges, no write access to your infrastructure, minimal data collected — because a vulnerability inventory is itself a target.",
  },
];

type FormState = "idle" | "submitting" | "success" | "duplicate" | "invalid" | "error";

export function Landing() {
  const [email, setEmail] = useState("");
  const [state, setState] = useState<FormState>("idle");

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setState("submitting");
    try {
      const res = await joinWaitlist(email);
      setState(res.status);
    } catch {
      setState("error");
    }
  }

  const submitted = state === "success" || state === "duplicate";

  return (
    <div className="min-h-screen bg-white dark:bg-slate-950">
      <header className="mx-auto flex max-w-6xl items-center justify-between px-6 py-6">
        <div className="flex items-center gap-2">
          <div className="flex size-8 items-center justify-center rounded-lg bg-brand-600 text-white">
            <ShieldCheck className="size-5" />
          </div>
          <span className="text-lg font-semibold text-slate-900 dark:text-white">Kepler</span>
        </div>
        <Link
          to="/login"
          className="text-sm font-semibold text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white"
        >
          Log in
        </Link>
      </header>

      <main className="mx-auto max-w-6xl px-6">
        <section className="relative grid items-center gap-16 py-20 sm:py-28 lg:grid-cols-2">
          <AuroraBackground />
          <div className="text-center lg:text-left">
            <h1 className="mx-auto max-w-xl text-4xl font-bold tracking-tight text-slate-900 sm:text-6xl lg:mx-0 dark:text-white">
              Know what&apos;s actually vulnerable.{" "}
              <span className="text-brand-600 dark:text-brand-400">Not what might be.</span>
            </h1>
            <p className="mx-auto mt-6 max-w-xl text-lg text-slate-600 lg:mx-0 dark:text-slate-400">
              Kepler scans your Linux infrastructure, matches it against real CVE
              data, and tells you exactly which findings need an upgrade versus
              which ones need a different kind of attention — read-only, minimal
              footprint, no agent sprawl.
            </p>

            <div className="mx-auto mt-10 max-w-md lg:mx-0">
              {submitted ? (
                <div className="flex items-center justify-center gap-2 rounded-lg bg-emerald-50 px-4 py-3 text-sm font-medium text-emerald-700 ring-1 ring-inset ring-emerald-600/20 lg:justify-start dark:bg-emerald-950/50 dark:text-emerald-400 dark:ring-emerald-400/30">
                  <CheckCircle2 className="size-5 shrink-0" />
                  {state === "duplicate"
                    ? "You're already on the list."
                    : "You're on the list — we'll be in touch."}
                </div>
              ) : (
                <form onSubmit={handleSubmit} className="flex gap-2">
                  <div className="flex-1 text-left">
                    <Input
                      type="email"
                      required
                      placeholder="you@company.com"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      aria-label="Email address"
                    />
                    {/* Honeypot: hidden from real users via CSS, catches naive
                        bots that fill in every field. Mirrors the server-side
                        form's own honeypot (web/internal/handlers/landing.go). */}
                    <input
                      type="text"
                      name="company_website"
                      tabIndex={-1}
                      autoComplete="off"
                      className="absolute h-0 w-0 opacity-0"
                      aria-hidden="true"
                    />
                  </div>
                  <Button type="submit" disabled={state === "submitting"}>
                    {state === "submitting" ? "Joining…" : "Join waitlist"}
                  </Button>
                </form>
              )}
              {state === "invalid" && (
                <p className="mt-2 text-sm text-red-600 dark:text-red-400">
                  That doesn&apos;t look like a valid email address.
                </p>
              )}
              {state === "error" && (
                <p className="mt-2 text-sm text-red-600 dark:text-red-400">
                  Something went wrong — try again in a moment.
                </p>
              )}
            </div>
          </div>

          <TiltPreviewCard>
            <div className="flex items-center justify-between border-b border-slate-100 px-4 py-3 dark:border-slate-800">
              <span className="text-xs font-semibold text-slate-500 dark:text-slate-400">
                Findings
              </span>
              <span className="rounded-full bg-slate-100 px-2 py-0.5 text-[11px] font-medium text-slate-500 dark:bg-slate-800 dark:text-slate-400">
                Example preview
              </span>
            </div>
            <div className="divide-y divide-slate-100 dark:divide-slate-800">
              {PREVIEW_FINDINGS.map((f) => (
                <div key={f.cveId} className="flex items-center gap-3 px-4 py-3 text-sm">
                  <div className="min-w-0 flex-1">
                    <div className="truncate font-medium text-slate-900 dark:text-white">{f.host}</div>
                    <div className="truncate font-mono text-xs text-slate-500 dark:text-slate-400">
                      {f.package} — {f.cveId}
                    </div>
                  </div>
                  <SeverityBadge severity={f.severity} />
                  <StatusBadge status={f.status} />
                </div>
              ))}
            </div>
          </TiltPreviewCard>
        </section>

        <section className="grid gap-8 border-t border-slate-200 py-20 sm:grid-cols-3 dark:border-slate-800">
          {FEATURES.map(({ icon: Icon, title, body }) => (
            <div key={title}>
              <div className="flex size-10 items-center justify-center rounded-lg bg-brand-50 text-brand-600 dark:bg-brand-500/10 dark:text-brand-400">
                <Icon className="size-5" />
              </div>
              <h2 className="mt-4 text-base font-semibold text-slate-900 dark:text-white">
                {title}
              </h2>
              <p className="mt-2 text-sm leading-relaxed text-slate-600 dark:text-slate-400">
                {body}
              </p>
            </div>
          ))}
        </section>
      </main>

      <footer className="border-t border-slate-200 py-8 text-center text-sm text-slate-500 dark:border-slate-800 dark:text-slate-500">
        Kepler — built for teams who'd rather fix real problems than chase noise.
      </footer>
    </div>
  );
}
