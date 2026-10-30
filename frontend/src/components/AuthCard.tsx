import { FormEvent, useEffect, useState } from "react";
import { checkStrength, login, register } from "../api";
import type { AuthResponse, Mode, Strength } from "../types";
import StrengthMeter from "./StrengthMeter";

interface Props {
  onResult: (mode: Mode, result: AuthResponse) => void;
  onNetworkError: (message: string | null) => void;
}

export default function AuthCard({ onResult, onNetworkError }: Props) {
  const [mode, setMode] = useState<Mode>("register");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [strength, setStrength] = useState<Strength | null>(null);
  const [errors, setErrors] = useState<string[]>([]);

  // Live strength preview while creating an account (waits 250 ms after typing stops).
  useEffect(() => {
    if (mode !== "register" || !password) {
      setStrength(null);
      return;
    }
    let cancelled = false;
    const timer = window.setTimeout(async () => {
      try {
        const result = await checkStrength(password, username);
        if (!cancelled) setStrength(result);
      } catch {
        // The preview is optional, so ignore network errors here.
      }
    }, 250);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [mode, password, username]);

  function switchMode(next: Mode) {
    setMode(next);
    setErrors([]);
    setPassword("");
  }

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setErrors([]);
    onNetworkError(null);
    try {
      const result =
        mode === "register" ? await register(username, password) : await login(username, password);
      setErrors(result.errors ?? []);
      onResult(mode, result);
      if (result.success) {
        setPassword("");
        if (mode === "register") setMode("login");
      } else if (mode === "login") {
        setPassword("");
      }
    } catch {
      onNetworkError("Can't reach the server. Start the Python backend on port 5000, then try again.");
    } finally {
      setBusy(false);
    }
  }

  const isRegister = mode === "register";

  return (
    <section className="card auth" aria-labelledby="auth-title">
      <div className="tabs" role="tablist" aria-label="Account action">
        <button
          type="button"
          role="tab"
          aria-selected={isRegister}
          className="tabs__tab"
          onClick={() => switchMode("register")}
        >
          Create account
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={!isRegister}
          className="tabs__tab"
          onClick={() => switchMode("login")}
        >
          Sign in
        </button>
      </div>

      <h2 id="auth-title" className="auth__title">
        {isRegister ? "Create your account" : "Welcome back"}
      </h2>

      {/* noValidate: the browser skips its own checks so the server's validation (Step 3) is what you see. */}
      <form onSubmit={handleSubmit} noValidate>
        <label className="field">
          <span className="field__label">Username</span>
          <input
            className="field__input"
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            autoCapitalize="none"
            spellCheck={false}
            maxLength={20}
            placeholder="3 to 20 letters, numbers, or underscores"
          />
        </label>

        <label className="field">
          <span className="field__label">Password</span>
          <span className="field__row">
            <input
              className="field__input"
              type={showPassword ? "text" : "password"}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete={isRegister ? "new-password" : "current-password"}
              maxLength={128}
              placeholder={isRegister ? "At least 8 characters" : "Your password"}
            />
            <button
              type="button"
              className="field__toggle"
              onClick={() => setShowPassword((s) => !s)}
              aria-pressed={showPassword}
            >
              {showPassword ? "Hide" : "Show"}
            </button>
          </span>
        </label>

        {isRegister && <StrengthMeter strength={strength} />}

        {errors.length > 0 && (
          <ul className="errors" role="alert">
            {errors.map((message) => (
              <li key={message}>{message}</li>
            ))}
          </ul>
        )}

        <button className="submit" type="submit" disabled={busy}>
          {busy ? "Checking..." : isRegister ? "Create account" : "Sign in"}
        </button>
      </form>
    </section>
  );
}
