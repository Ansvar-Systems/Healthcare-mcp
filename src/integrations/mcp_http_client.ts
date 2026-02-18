export interface McpToolSummary {
  name: string;
  description?: string;
}

interface JsonRpcSuccess {
  jsonrpc: '2.0';
  id: number;
  result: unknown;
}

interface JsonRpcError {
  jsonrpc: '2.0';
  id: number | null;
  error: {
    code: number;
    message: string;
    data?: unknown;
  };
}

type JsonRpcResponse = JsonRpcSuccess | JsonRpcError;

export interface McpCallToolResult {
  raw: unknown;
  parsed: unknown;
  text: string;
}

export class McpHttpClient {
  private endpoint: string;

  private sessionId: string | null = null;

  private requestId = 1;

  private timeoutMs: number;

  private clientName: string;

  private clientVersion: string;

  constructor(options: {
    endpoint: string;
    timeoutMs?: number;
    clientName?: string;
    clientVersion?: string;
  }) {
    this.endpoint = options.endpoint;
    this.timeoutMs = options.timeoutMs ?? 10000;
    this.clientName = options.clientName ?? 'healthcare-mcp-router';
    this.clientVersion = options.clientVersion ?? '0.1.0';
  }

  getSessionId(): string | null {
    return this.sessionId;
  }

  async initialize(): Promise<unknown> {
    const result = await this.rpcRequest('initialize', {
      protocolVersion: '2025-03-26',
      capabilities: {},
      clientInfo: {
        name: this.clientName,
        version: this.clientVersion,
      },
    });

    try {
      // Some MCP servers do not accept explicit initialized notifications over this transport.
      // Keep initialization resilient by treating notification failure as non-fatal.
      await this.rpcNotification('notifications/initialized', {});
    } catch {
      // Best-effort notification only.
    }
    return result;
  }

  async listTools(): Promise<McpToolSummary[]> {
    const result = (await this.rpcRequest('tools/list', {})) as {
      tools?: Array<{ name?: string; description?: string }>;
    };

    const tools = Array.isArray(result?.tools) ? result.tools : [];
    return tools
      .filter((tool) => typeof tool.name === 'string')
      .map((tool) => ({
        name: String(tool.name),
        description: typeof tool.description === 'string' ? tool.description : undefined,
      }));
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<McpCallToolResult> {
    const result = (await this.rpcRequest('tools/call', {
      name,
      arguments: args,
    })) as {
      content?: Array<{ type?: string; text?: string }>;
    };

    const textBlocks = Array.isArray(result?.content)
      ? result.content
          .filter((entry) => entry?.type === 'text' && typeof entry.text === 'string')
          .map((entry) => String(entry.text))
      : [];

    const text = textBlocks.join('\n').trim();
    const parsed = this.tryParseJson(text);

    return {
      raw: result,
      parsed,
      text,
    };
  }

  private tryParseJson(text: string): unknown {
    if (!text) {
      return null;
    }

    try {
      return JSON.parse(text) as unknown;
    } catch {
      return text;
    }
  }

  private parseSseJsonRpc(text: string): JsonRpcResponse {
    const objects: JsonRpcResponse[] = [];
    const events = text.split(/\n\n+/);

    for (const eventBlock of events) {
      const lines = eventBlock.split(/\r?\n/);
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed.startsWith('data:')) {
          continue;
        }

        const data = trimmed.slice(5).trim();
        if (!data || data === '[DONE]') {
          continue;
        }

        try {
          const parsed = JSON.parse(data) as JsonRpcResponse;
          if (parsed && typeof parsed === 'object' && 'jsonrpc' in parsed) {
            objects.push(parsed);
          }
        } catch {
          // Ignore non-JSON data frames.
        }
      }
    }

    if (objects.length === 0) {
      throw new Error('No JSON-RPC payload found in SSE response');
    }

    return objects[objects.length - 1];
  }

  private async rpcRequest(method: string, params: unknown): Promise<unknown> {
    const requestId = this.requestId++;

    const body = {
      jsonrpc: '2.0' as const,
      id: requestId,
      method,
      params,
    };

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
    };

    if (this.sessionId) {
      headers['Mcp-Session-Id'] = this.sessionId;
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await fetch(this.endpoint, {
        method: 'POST',
        headers,
        body: JSON.stringify(body),
        signal: controller.signal,
      });

      const sessionHeader = response.headers.get('mcp-session-id');
      if (sessionHeader) {
        this.sessionId = sessionHeader;
      }

      if (!response.ok) {
        const text = await response.text();
        throw new Error(`HTTP ${response.status}: ${text || 'empty response'}`);
      }

      const contentType = response.headers.get('content-type') ?? '';
      const rawBody = await response.text();
      const payload = contentType.includes('text/event-stream')
        ? this.parseSseJsonRpc(rawBody)
        : (JSON.parse(rawBody) as JsonRpcResponse);

      if ('error' in payload) {
        throw new Error(`RPC ${payload.error.code}: ${payload.error.message}`);
      }

      return payload.result;
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') {
        throw new Error(`MCP request timed out after ${this.timeoutMs}ms`);
      }
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }

  private async rpcNotification(method: string, params: unknown): Promise<void> {
    const body = {
      jsonrpc: '2.0' as const,
      method,
      params,
    };

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
    };

    if (this.sessionId) {
      headers['Mcp-Session-Id'] = this.sessionId;
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await fetch(this.endpoint, {
        method: 'POST',
        headers,
        body: JSON.stringify(body),
        signal: controller.signal,
      });

      const sessionHeader = response.headers.get('mcp-session-id');
      if (sessionHeader) {
        this.sessionId = sessionHeader;
      }

      if (!response.ok) {
        const text = await response.text();
        throw new Error(`Notification failed (${response.status}): ${text || 'empty response'}`);
      }
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') {
        throw new Error(`MCP notification timed out after ${this.timeoutMs}ms`);
      }
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }
}
