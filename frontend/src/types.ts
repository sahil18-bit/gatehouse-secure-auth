export type Mode = "register" | "login";
export type StrengthLabel = "Weak" | "Moderate" | "Strong";

export interface Strength {
  label: StrengthLabel;
  score: number;
  max: number;
  feedback: string[];
}

export interface TraceStep {
  step: number;
  title: string;
  status: "pass" | "fail" | "warn" | "info";
  detail: string;
}

export interface SecurityAlert {
  id: number;
  time: string;
  level: "warning" | "critical";
  message: string;
}

export interface AuthResponse {
  success: boolean;
  status: string;
  message: string;
  errors?: string[];
  strength?: Strength | null;
  failed_attempts?: number;
  attempts_until_lock?: number;
  locked?: boolean;
  retry_after?: number;
  alert?: SecurityAlert | null;
  trace: TraceStep[];
}

export interface StatusResponse {
  registered_users: number;
  total_failed_attempts: number;
  alerts: SecurityAlert[];
  thresholds: { alert: number; lock: number; lock_seconds: number };
}

export interface OwaspItem {
  id: string;
  name: string;
  risk: string;
  in_this_app: string;
  prevention: string;
}

export interface AiTopic {
  kind: "application" | "risk";
  title: string;
  summary: string;
  example: string;
  defence: string;
}

export interface LastResult {
  id: number;
  mode: Mode;
  result: AuthResponse;
}
