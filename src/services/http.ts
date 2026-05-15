export class UpstreamHttpError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly responseText: string,
  ) {
    super(message);
  }
}

export async function fetchJson<T>(
  url: string,
  options: RequestInit & { timeoutMs?: number } = {},
): Promise<T> {
  const timeoutMs = options.timeoutMs ?? 15000;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
    });
    if (!response.ok) {
      const text = await response.text().catch(() => "");
      throw new UpstreamHttpError(`Upstream request failed with ${response.status}`, response.status, text);
    }
    return (await response.json()) as T;
  } finally {
    clearTimeout(timeout);
  }
}
