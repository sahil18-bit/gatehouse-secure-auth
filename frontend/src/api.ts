import type {
  AiTopic,
  AuthResponse,
  OwaspItem,
  StatusResponse,
  Strength,
} from "./types";

// The backend sends structured JSON for failures too (400, 401, 409, 423),
// so we always parse the body and let callers read `success`.
async function send<T>(path: string, body?: unknown): Promise<T> {
  const response = await fetch(path, {
    method: body === undefined ? "GET" : "POST",
    headers: body === undefined ? undefined : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return (await response.json()) as T;
}

export const register = (username: string, password: string) =>
  send<AuthResponse>("/api/register", { username, password });

export const login = (username: string, password: string) =>
  send<AuthResponse>("/api/login", { username, password });

export const checkStrength = (password: string, username: string) =>
  send<Strength>("/api/strength", { password, username });

export const getStatus = () => send<StatusResponse>("/api/status");

export const getOwasp = async () =>
  (await send<{ edition: string; items: OwaspItem[] }>("/api/owasp"));

export const getAiSecurity = async () =>
  (await send<{ topics: AiTopic[] }>("/api/ai-security")).topics;
