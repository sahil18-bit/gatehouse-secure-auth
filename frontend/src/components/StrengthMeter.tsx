import type { Strength } from "../types";

interface Props {
  strength: Strength | null;
}

const FILLED: Record<Strength["label"], number> = { Weak: 1, Moderate: 2, Strong: 3 };

export default function StrengthMeter({ strength }: Props) {
  if (!strength) return null;
  const filled = FILLED[strength.label];
  return (
    <div className="meter" aria-live="polite">
      <div className="meter__bars" aria-hidden="true">
        {[1, 2, 3].map((n) => (
          <span
            key={n}
            className={`meter__bar ${n <= filled ? `meter__bar--${strength.label.toLowerCase()}` : ""}`}
          />
        ))}
      </div>
      <p className={`meter__label meter__label--${strength.label.toLowerCase()}`}>
        Password strength: {strength.label}
      </p>
      {strength.feedback.length > 0 && (
        <ul className="meter__tips">
          {strength.feedback.map((tip) => (
            <li key={tip}>{tip}</li>
          ))}
        </ul>
      )}
    </div>
  );
}
