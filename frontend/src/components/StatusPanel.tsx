import type { LastResult, StatusResponse } from "../types";

interface Props {
  last: LastResult | null;
  status: StatusResponse | null;
  networkError: string | null;
}

const ICON = { pass: "✓", fail: "✕", warn: "!", info: "i" } as const;

export default function StatusPanel({ last, status, networkError }: Props) {
  const result = last?.result;
  const alerts = status?.alerts ?? [];

  let lockText = "Not locked";
  if (result?.locked) lockText = `Locked ${result.retry_after ?? 0}s`;

  return (
    <aside className="panel" aria-label="Security status" aria-live="polite">
      <h2 className="panel__title">Security status</h2>

      {networkError && (
        <p className="panel__network" role="alert">
          {networkError}
        </p>
      )}

      {!last || !result ? (
        <div className="panel__empty">
          <p className="panel__empty-title">Nothing to report yet</p>
          <p>Create an account or sign in. Every check the server runs will appear here.</p>
        </div>
      ) : (
        <>
          <div className={`verdict ${result.success ? "verdict--good" : "verdict--bad"}`}>
            <span className="verdict__dot" aria-hidden="true" />
            <div>
              <p className="verdict__status">{result.status}</p>
              <p className="verdict__message">{result.message}</p>
            </div>
          </div>

          <dl className="stats">
            <div>
              <dt>Accounts</dt>
              <dd>{status?.registered_users ?? "-"}</dd>
            </div>
            <div>
              <dt>Failed attempts</dt>
              <dd>{last.mode === "login" ? result.failed_attempts ?? 0 : "-"}</dd>
            </div>
            <div>
              <dt>Lock</dt>
              <dd>{last.mode === "login" ? lockText : "-"}</dd>
            </div>
          </dl>

          <h3 className="panel__sub">What the server checked</h3>
          <ol className="trace" key={last.id}>
            {result.trace.map((item, index) => (
              <li
                key={`${item.step}-${index}`}
                className={`trace__item trace__item--${item.status}`}
                style={{ ["--i" as string]: index }}
              >
                <span className="trace__icon" aria-label={item.status}>
                  {ICON[item.status]}
                </span>
                <div>
                  <p className="trace__title">
                    <span className="trace__step">Step {item.step}</span> {item.title}
                  </p>
                  <p className="trace__detail">{item.detail}</p>
                </div>
              </li>
            ))}
          </ol>
        </>
      )}

      <h3 className="panel__sub">Security alerts</h3>
      {alerts.length === 0 ? (
        <p className="panel__quiet">
          No alerts. One is raised after {status?.thresholds.alert ?? 3} failed sign-ins in a row.
        </p>
      ) : (
        <ul className="alerts">
          {alerts.slice(0, 4).map((alert) => (
            <li key={alert.id} className={`alerts__item alerts__item--${alert.level}`}>
              <p className="alerts__level">
                {alert.level === "critical" ? "Critical" : "Warning"} at{" "}
                {new Date(alert.time).toLocaleTimeString()}
              </p>
              <p>{alert.message}</p>
            </li>
          ))}
        </ul>
      )}
    </aside>
  );
}
