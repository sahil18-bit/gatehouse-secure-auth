import { useCallback, useEffect, useState } from "react";
import AuthCard from "./components/AuthCard";
import LearnSection from "./components/LearnSection";
import StatusPanel from "./components/StatusPanel";
import { getStatus } from "./api";
import type { AuthResponse, LastResult, Mode, StatusResponse } from "./types";

export default function App() {
  const [status, setStatus] = useState<StatusResponse | null>(null);
  const [last, setLast] = useState<LastResult | null>(null);
  const [networkError, setNetworkError] = useState<string | null>(null);

  const refreshStatus = useCallback(async () => {
    try {
      setStatus(await getStatus());
    } catch {
      // The error banner appears when the person tries an action.
    }
  }, []);

  useEffect(() => {
    void refreshStatus();
  }, [refreshStatus]);

  const handleResult = useCallback(
    (mode: Mode, result: AuthResponse) => {
      setLast((prev) => ({ id: (prev?.id ?? 0) + 1, mode, result }));
      void refreshStatus();
    },
    [refreshStatus]
  );

  return (
    <div className="page">
      <header className="masthead">
        <h1>Gatehouse</h1>
        <p>
          Create an account, sign in, and watch the checks the server runs at every step.
        </p>
      </header>

      <main className="layout">
        <div className="layout__main">
          <AuthCard onResult={handleResult} onNetworkError={setNetworkError} />
          <LearnSection />
        </div>
        <StatusPanel last={last} status={status} networkError={networkError} />
      </main>

      <footer className="footer">
        Teaching demo. Accounts live in server memory and disappear when the backend restarts.
      </footer>
    </div>
  );
}
