import { ShieldCheck } from "lucide-react";
import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { verifyCredentials } from "../lib/api";
import { storeCredentials } from "../lib/auth";
import { Button } from "../components/ui/Button";
import { Input } from "../components/ui/Input";

export function Login() {
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      // Verified against a real request to the dashboard API, not a
      // separate "check credentials" endpoint — this is still plain HTTP
      // Basic Auth server-side (web/internal/auth), just presented through
      // a styled form instead of the browser's native auth popup.
      const ok = await verifyCredentials(username, password);
      if (!ok) {
        setError("Incorrect username or password.");
        return;
      }
      storeCredentials({ username, password });
      navigate("/dashboard");
    } catch {
      setError("Couldn't reach the backend — check it's running.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-50 px-6 dark:bg-slate-950">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex flex-col items-center gap-3">
          <div className="flex size-10 items-center justify-center rounded-lg bg-brand-600 text-white">
            <ShieldCheck className="size-6" />
          </div>
          <h1 className="text-xl font-semibold text-slate-900 dark:text-white">
            Sign in to Kepler
          </h1>
        </div>

        <form
          onSubmit={handleSubmit}
          className="space-y-4 rounded-xl bg-white p-6 shadow-sm ring-1 ring-slate-200 dark:bg-slate-900 dark:ring-slate-800"
        >
          <div>
            <label htmlFor="username" className="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-300">
              Username
            </label>
            <Input
              id="username"
              required
              autoFocus
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
          </div>
          <div>
            <label htmlFor="password" className="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-300">
              Password
            </label>
            <Input
              id="password"
              type="password"
              required
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
          {error && (
            <p className="text-sm text-red-600 dark:text-red-400" role="alert">
              {error}
            </p>
          )}
          <Button type="submit" className="w-full" disabled={submitting}>
            {submitting ? "Signing in…" : "Sign in"}
          </Button>
        </form>

        <p className="mt-4 text-center text-xs text-slate-400 dark:text-slate-500">
          Single operator credential for v1 — no self-service accounts yet.
        </p>
      </div>
    </div>
  );
}
