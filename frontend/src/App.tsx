import { Navigate, Route, Routes } from "react-router-dom";
import { getStoredCredentials } from "./lib/auth";
import { Dashboard } from "./pages/Dashboard";
import { Landing } from "./pages/Landing";
import { Login } from "./pages/Login";

/**
 * Gates /dashboard on a stored credential. This is a UX guard only, not a
 * security boundary — the real gate is the backend's RequireBasicAuth
 * middleware; a missing/invalid credential here just means the first API
 * call fails and Dashboard itself redirects to /login (see its
 * UnauthorizedError handling). This check just skips the flash of a
 * loading dashboard for the common case of "never logged in."
 */
function RequireAuth({ children }: { children: React.ReactNode }) {
  if (!getStoredCredentials()) {
    return <Navigate to="/login" replace />;
  }
  return <>{children}</>;
}

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route path="/login" element={<Login />} />
      <Route
        path="/dashboard"
        element={
          <RequireAuth>
            <Dashboard />
          </RequireAuth>
        }
      />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
