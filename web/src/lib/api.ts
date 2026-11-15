const TOKEN_KEY = "dystopia.access_token";
export const UNAUTHORIZED_EVENT = "dystopia:unauthorized";

function tokenPayload(token: string): Record<string, unknown> | null {
  try {
    const payload = token.split(".")[1];
    if (!payload) return null;
    const padded = payload.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(payload.length / 4) * 4, "=");
    return JSON.parse(atob(padded)) as Record<string, unknown>;
  } catch {
    return null;
  }
}

function tokenExpiry(token: string): number | null {
  const data = tokenPayload(token);
  return data && typeof data.exp === "number" ? data.exp : null;
}

function notifyUnauthorized() {
  clearToken();
  window.dispatchEvent(new Event(UNAUTHORIZED_EVENT));
}

export class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

export function getToken(): string | null {
  try {
    const token = window.localStorage.getItem(TOKEN_KEY);
    if (!token) return null;
    const exp = tokenExpiry(token);
    if (exp !== null && exp * 1000 <= Date.now()) {
      window.localStorage.removeItem(TOKEN_KEY);
      return null;
    }
    return token;
  } catch {
    return null;
  }
}

export function setToken(token: string) {
  window.localStorage.setItem(TOKEN_KEY, token);
}

export function getRole(): string | null {
  let token: string | null = null;
  try {
    token = window.localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
  if (!token) return null;
  const payload = tokenPayload(token);
  return payload && typeof payload.role === "string" ? payload.role : null;
}

export function clearToken() {
  window.localStorage.removeItem(TOKEN_KEY);
}

export async function login(username: string, password: string): Promise<string> {
  const response = await fetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!response.ok) {
    throw new ApiError(response.status === 401 ? "Usuario o contraseña incorrectos" : "No se pudo iniciar sesión", response.status);
  }
  const payload = (await response.json()) as { access_token?: string };
  if (!payload.access_token) throw new ApiError("Respuesta de autenticación inválida", 500);
  setToken(payload.access_token);
  return payload.access_token;
}

export async function apiPut<T>(path: string, body: unknown): Promise<T> {
  return apiSend<T>("PUT", path, body);
}

export async function apiPost<T>(path: string, body?: unknown): Promise<T> {
  return apiSend<T>("POST", path, body);
}

export async function apiDelete(path: string): Promise<void> {
  await apiSend<void>("DELETE", path);
}

async function apiSend<T>(method: "PUT" | "POST" | "DELETE", path: string, body?: unknown): Promise<T> {
  const token = getToken();
  if (!token) throw new ApiError("Inicia sesión para guardar cambios", 401);
  const response = await fetch(path, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
      ...(body === undefined ? {} : { "Content-Type": "application/json" }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  if (response.status === 401) {
    notifyUnauthorized();
    throw new ApiError("Sesión expirada; inicia sesión de nuevo", 401);
  }
  if (!response.ok) {
    let detail = response.status === 409 ? "Cambios en conflicto: recarga la ficha antes de guardar" :
      response.status === 403 ? "Tu rol no permite ejecutar esta acción" :
      response.status === 404 ? "El recurso ya no existe" : "No se pudo completar la acción";
    try {
      const payload = (await response.json()) as { detail?: string };
      if (typeof payload.detail === "string" && response.status !== 422) detail = payload.detail;
    } catch { /* Keep actionable message. */ }
    throw new ApiError(detail, response.status);
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export async function apiGet<T>(path: string, signal?: AbortSignal): Promise<T> {
  const token = getToken();
  const headers: Record<string, string> = { Accept: "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  const response = await fetch(path, { headers, signal });
  if (response.status === 401) {
    notifyUnauthorized();
    throw new ApiError("Sesión expirada", 401);
  }
  if (!response.ok) {
    let detail = "El servicio analítico no está disponible";
    try {
      const body = (await response.json()) as { detail?: string };
      if (typeof body.detail === "string") detail = body.detail;
    } catch {
      // Keep the generic message.
    }
    throw new ApiError(detail, response.status);
  }
  return (await response.json()) as T;
}
