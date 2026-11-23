import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import {
  createPluginLogger,
  parseOpenAIChatUsage,
  parseOpenAIResponsesUsage,
  silentPluginLogger,
  type PluginContext,
  type ProviderConnection,
  type ProviderHandler,
} from "@viateai/sdk";
import {
  audioSpeech,
  audioTranscriptions,
  chatCompletions,
  closeXaiOauthLoopback,
  embeddings,
  exchangeOAuth,
  imageEdits,
  imageGenerations,
  keepalive,
  videoEdits,
  videoExtensions,
  videoGenerations,
  videoResult,
  listModels,
  normalizeCredentials,
  parseCredentials,
  plugin,
  responses,
  responsesCompact,
  startOAuth,
  subscription,
} from "./index.js";

const originalFetch = globalThis.fetch;
const CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828";

afterEach(async () => {
  globalThis.fetch = originalFetch;
  await closeXaiOauthLoopback();
});

describe("xai-oauth plugin", () => {
  it("registers one provider matching the plugin id", () => {
    const providers: ProviderHandler[] = [];
    const ctx: PluginContext = {
      registerProvider(handler) {
        providers.push(handler);
      },
      log: silentPluginLogger(),
    };
    plugin.register(ctx);
    assert.equal(plugin.id, "xai-oauth");
    assert.equal(providers.length, 1);
    assert.equal(providers[0]?.id, "xai-oauth");
    assert.equal(typeof providers[0]?.startOAuth, "function");
    assert.equal(typeof providers[0]?.exchangeOAuth, "function");
    assert.equal(typeof providers[0]?.keepalive, "function");
    assert.equal(typeof providers[0]?.subscription, "function");
    assert.equal(typeof providers[0]?.responsesCompact, "function");
    assert.equal(typeof providers[0]?.imageGenerations, "function");
    assert.equal(typeof providers[0]?.imageEdits, "function");
    const registered = providers[0] as ProviderHandler & {
      audioTranscriptions?: unknown;
      audioSpeech?: unknown;
      videoGenerations?: unknown;
      videoEdits?: unknown;
      videoExtensions?: unknown;
      videoResult?: unknown;
    };
    assert.equal(typeof registered.audioTranscriptions, "function");
    assert.equal(typeof registered.audioSpeech, "function");
    assert.equal(typeof registered.videoGenerations, "function");
    assert.equal(typeof registered.videoEdits, "function");
    assert.equal(typeof registered.videoExtensions, "function");
    assert.equal(typeof registered.videoResult, "function");
  });

  it("normalizes token paste and OAuth token responses", () => {
    const idToken = jwt({ email: "user@example.com", name: "Grok User" });
    const before = Date.now();
    const normalized = normalizeCredentials({
      access_token: "access",
      refresh_token: "refresh",
      id_token: idToken,
      expires_in: 3_600,
    });
    const after = Date.now();
    assert.equal(normalized.displayLabel, "user@example.com");
    const credentials = normalized.credentials as {
      accessToken?: string;
      refreshToken?: string;
      idToken?: string;
      email?: string;
      expiresAt?: string;
    };
    assert.equal(credentials.accessToken, "access");
    assert.equal(credentials.refreshToken, "refresh");
    assert.equal(credentials.idToken, idToken);
    assert.equal(credentials.email, "user@example.com");
    const expiresAt = Date.parse(credentials.expiresAt ?? "");
    assert.ok(expiresAt >= before + 3_600_000 && expiresAt <= after + 3_600_000);
    assert.deepEqual(normalizeCredentials(parseCredentials("raw-token")).credentials, {
      accessToken: "raw-token",
    });
  });

  it("builds the official PKCE authorization URL and exchanges the code", async () => {
    const started = await startOAuth({
      connectionId: "c1",
      credentials: {},
      callbackUrl: "http://127.0.0.1:4317/api/admin/oauth/callback?state=abc",
    });
    assert.equal(started.type, "authorization_url");
    if (started.type !== "authorization_url") return;
    const url = new URL(started.authorizationUrl);
    assert.equal(url.origin, "https://auth.x.ai");
    assert.equal(url.pathname, "/oauth2/authorize");
    assert.equal(url.searchParams.get("client_id"), CLIENT_ID);
    assert.equal(
      url.searchParams.get("scope"),
      "openid profile email offline_access grok-cli:access api:access",
    );
    assert.equal(url.searchParams.get("redirect_uri"), "http://127.0.0.1:56121/callback");
    assert.equal(url.searchParams.get("code_challenge_method"), "S256");
    assert.equal(url.searchParams.get("plan"), "generic");
    assert.equal(url.searchParams.get("referrer"), "cli-proxy-api");
    assert.equal(url.searchParams.get("state"), "abc");
    assert.ok(url.searchParams.get("nonce"));
    const session = started.session as { verifier?: string; redirectUri?: string };
    assert.equal(session.verifier?.length, 128);
    assert.equal(session.redirectUri, "http://127.0.0.1:56121/callback");

    const bounced = await fetch("http://127.0.0.1:56121/callback?code=auth-code&state=abc", {
      redirect: "manual",
    });
    assert.equal(bounced.status, 302);
    const location = new URL(bounced.headers.get("location") ?? "");
    assert.equal(location.origin, "http://127.0.0.1:4317");
    assert.equal(location.pathname, "/api/admin/oauth/callback");
    assert.equal(location.searchParams.get("state"), "abc");
    assert.equal(location.searchParams.get("code"), "auth-code");

    globalThis.fetch = async (input, init) => {
      assert.equal(String(input), "https://auth.x.ai/oauth2/token");
      assert.equal(init?.method, "POST");
      const headers = new Headers(init?.headers);
      assert.equal(headers.get("content-type"), "application/x-www-form-urlencoded");
      const body = new URLSearchParams(String(init?.body));
      assert.equal(body.get("grant_type"), "authorization_code");
      assert.equal(body.get("client_id"), CLIENT_ID);
      assert.equal(body.get("code"), "auth-code");
      assert.equal(body.get("redirect_uri"), "http://127.0.0.1:56121/callback");
      assert.equal(body.get("code_verifier"), session.verifier);
      return Response.json({
        access_token: "access",
        refresh_token: "refresh",
        id_token: jwt({ email: "user@example.com" }),
        expires_in: 3_600,
      });
    };

    const exchanged = await exchangeOAuth({
      connectionId: "c1",
      credentials: {},
      code: "auth-code",
      session: started.session,
    });
    assert.equal(
      exchanged.credentials && typeof exchanged.credentials === "object" && "accessToken" in exchanged.credentials
        ? exchanged.credentials.accessToken
        : undefined,
      "access",
    );
    assert.equal(exchanged.displayLabel, "user@example.com");
  });

  it("refreshes expired tokens through keepalive", async () => {
    globalThis.fetch = async (input, init) => {
      assert.equal(String(input), "https://auth.x.ai/oauth2/token");
      const body = new URLSearchParams(String(init?.body));
      assert.equal(body.get("grant_type"), "refresh_token");
      assert.equal(body.get("client_id"), CLIENT_ID);
      assert.equal(body.get("refresh_token"), "old-refresh");
      return Response.json({
        access_token: "new-access",
        refresh_token: "new-refresh",
        expires_in: 7_200,
      });
    };
    const result = await keepalive({
      connectionId: "c1",
      credentials: {
        accessToken: "old-access",
        refreshToken: "old-refresh",
        expiresAt: new Date(Date.now() - 1_000).toISOString(),
      },
      signal: new AbortController().signal,
      reason: "timer",
      log: silentPluginLogger(),
    });
    assert.equal(result.status, "ok");
    assert.equal(
      result.credentials && typeof result.credentials === "object" && "accessToken" in result.credentials
        ? result.credentials.accessToken
        : undefined,
      "new-access",
    );
  });

  it("records upstream OAuth error on keepalive refresh 400", async () => {
    const writes: Array<{ level: string; fields?: Record<string, unknown>; message: string }> = [];
    globalThis.fetch = async () => Response.json(
      { error: "invalid_grant", error_description: "Refresh token has been revoked" },
      { status: 400 },
    );
    const result = await keepalive({
      connectionId: "c1",
      credentials: {
        accessToken: "old-access",
        refreshToken: "old-refresh",
        expiresAt: new Date(Date.now() - 1_000).toISOString(),
      },
      signal: new AbortController().signal,
      reason: "timer",
      log: createPluginLogger((level, fields, message) => {
        writes.push({ level, fields, message });
      }),
    });
    assert.equal(result.status, "needs_reauth");
    assert.equal(
      result.error,
      "xAI token refresh failed (400): Refresh token has been revoked",
    );
    assert.deepEqual(writes, [{
      level: "warn",
      fields: {
        status: "needs_reauth",
        error: "xAI token refresh failed (400): Refresh token has been revoked",
        httpStatus: 400,
      },
      message: "token refresh failed",
    }]);
  });

  it("maps weekly credits, prepaid cents, and product usage", async () => {
    const seen: string[] = [];
    globalThis.fetch = async (input, init) => {
      const url = String(input);
      seen.push(url);
      assert.equal(init?.method, "GET");
      assert.equal(init?.redirect, "manual");
      const headers = new Headers(init?.headers);
      assert.equal(headers.get("authorization"), "Bearer access");
      assert.equal(headers.get("x-grok-client-mode"), "cli");
      if (url.endsWith("/user?include=subscription")) {
        return Response.json({ subscriptionTier: "SuperGrok" });
      }
      assert.equal(url, "https://cli-chat-proxy.grok.com/v1/billing?format=credits");
      return Response.json({
        config: {
          creditUsagePercent: 37.5,
          currentPeriod: { type: "WEEKLY", end: "2026-11-02T00:00:00.000Z" },
          prepaidBalance: { val: 250 },
          productUsage: [
            { product: "Grok Build", usagePercent: 12 },
            { product: "Grok Build", usagePercent: 4 },
            { product: "Imagine", usagePercent: 140 },
            { product: "", usagePercent: 1 },
          ],
        },
      });
    };
    const result = await subscription({
      connectionId: "c1",
      credentials: { accessToken: "access" },
      signal: new AbortController().signal,
      log: silentPluginLogger(),
    });
    assert.deepEqual(seen.sort(), [
      "https://cli-chat-proxy.grok.com/v1/billing?format=credits",
      "https://cli-chat-proxy.grok.com/v1/user?include=subscription",
    ]);
    assert.equal(result.status, "ok");
    assert.equal(result.plan, "SuperGrok");
    assert.equal(result.nextDueMs, 10 * 60 * 1000);
    assert.equal(result.usages?.length, 4);
    assert.deepEqual(result.usages?.[0], {
      type: "credits",
      label: "Weekly credits",
      group: "Plan",
      unit: "percent",
      used: 37.5,
      limit: 100,
      remaining: 62.5,
      resetsAt: "2026-11-02T00:00:00.000Z",
    });
    assert.equal(result.usages?.[1]?.type, "prepaid");
    assert.equal(result.usages?.[1]?.remaining, 2.5);
    assert.equal(result.usages?.[1]?.currency, "USD");
    assert.equal(result.usages?.[2]?.type, "product:grok_build");
    assert.equal(result.usages?.[2]?.label, "Grok Build");
    assert.equal(result.usages?.[2]?.used, 12);
    assert.equal(result.usages?.[3]?.type, "product:grok_build:2");
    assert.equal(result.usages?.[3]?.used, 4);
  });

  it("marks an expired xAI session for reauth and hides transport failures", async () => {
    const writes: Array<{ level: string; fields?: Record<string, unknown>; message: string }> = [];
    const log = createPluginLogger((level, fields, message) => {
      writes.push({ level, fields, message });
    });
    globalThis.fetch = async () => new Response("no", { status: 401 });
    const expired = await subscription({
      connectionId: "c1",
      credentials: { accessToken: "access" },
      signal: new AbortController().signal,
      log,
    });
    assert.equal(expired.status, "needs_reauth");
    assert.equal(expired.error, "xAI session expired");

    globalThis.fetch = async () => {
      throw new Error("connect ECONNREFUSED bearer secret-token");
    };
    const failed = await subscription({
      connectionId: "c1",
      credentials: { accessToken: "secret-token" },
      signal: new AbortController().signal,
      log,
    });
    assert.equal(failed.status, "failed");
    assert.equal(failed.error, "xAI usage request failed");
    assert.equal(JSON.stringify(failed).includes("secret-token"), false);
    assert.equal(JSON.stringify(writes).includes("secret-token"), false);
    assert.equal(writes[0]?.message, "subscription refresh failed");
    assert.equal(writes[0]?.fields?.httpStatus, 401);
    assert.equal(writes[1]?.fields?.status, "failed");
  });

  it("proxies chat, responses, embeddings, and models to api.x.ai", async () => {
    const seen: Array<{ url: string; body?: Record<string, unknown>; authorization?: string | null }> = [];
    globalThis.fetch = async (input, init) => {
      const url = String(input);
      const body = init?.body ? JSON.parse(String(init.body)) as Record<string, unknown> : undefined;
      seen.push({
        url,
        body,
        authorization: new Headers(init?.headers).get("authorization"),
      });
      if (url.endsWith("/models")) {
        return Response.json({ object: "list", data: [{ id: "grok-4.5", owned_by: "xai" }] });
      }
      return Response.json({ id: "ok", object: url.includes("/responses") ? "response" : "chat.completion" });
    };
    const creds = connection({ accessToken: "access" });
    const chat = await chatCompletions(
      { body: { model: "grok-4.5", messages: [{ role: "user", content: "hi" }] }, headers: {} },
      creds,
    );
    const native = await responses(
      { body: { model: "grok-4.5", input: "hi" }, headers: {} },
      creds,
    );
    const vectors = await embeddings(
      { body: { model: "text-embedding-3-small", input: "hi" }, headers: {} },
      creds,
    );
    const models = await listModels({ headers: {} }, creds);
    assert.equal(seen[0]?.url, "https://api.x.ai/v1/chat/completions");
    assert.equal(seen[0]?.body?.model, "grok-4.5");
    assert.equal(seen[0]?.authorization, "Bearer access");
    assert.equal(seen[1]?.url, "https://api.x.ai/v1/responses");
    assert.equal(seen[1]?.body?.input, "hi");
    assert.equal(seen[2]?.url, "https://api.x.ai/v1/embeddings");
    assert.equal(seen[3]?.url, "https://api.x.ai/v1/models");
    assert.equal(chat.status, 200);
    assert.equal(native.status, 200);
    assert.equal(vectors.status, 200);
    assert.deepEqual(models, {
      object: "list",
      data: [{ id: "grok-4.5", object: "model", owned_by: "xai" }],
    });
    assert.equal(chat.parseUsage, parseOpenAIChatUsage);
    assert.equal(native.parseUsage, parseOpenAIResponsesUsage);
    assert.equal(vectors.parseUsage, undefined);
  });

  it("proxies compact requests to /responses/compact without stream or include", async () => {
    let upstreamUrl = "";
    let upstreamBody: Record<string, unknown> | undefined;
    let accept = "";
    let authorization: string | null = null;
    globalThis.fetch = async (input, init) => {
      upstreamUrl = String(input);
      const headers = new Headers(init?.headers);
      accept = String(headers.get("accept") ?? "");
      authorization = headers.get("authorization");
      upstreamBody = JSON.parse(String(init?.body)) as Record<string, unknown>;
      return Response.json({
        id: "resp_compact",
        object: "response",
        output: [{ type: "compacted", id: "cmp_1" }],
      });
    };
    const result = await responsesCompact(
      {
        body: {
          model: "grok-4.5",
          input: "hi",
          stream: false,
          store: true,
          include: ["reasoning.encrypted_content"],
          prompt_cache_key: "thread-1",
        },
        headers: {},
      },
      connection({ accessToken: "access" }),
    );
    assert.equal(upstreamUrl, "https://api.x.ai/v1/responses/compact");
    assert.equal(accept, "application/json");
    assert.equal(authorization, "Bearer access");
    assert.equal(upstreamBody?.input, "hi");
    assert.equal(upstreamBody?.prompt_cache_key, "thread-1");
    assert.equal(upstreamBody?.stream, undefined);
    assert.equal(upstreamBody?.store, undefined);
    assert.equal(upstreamBody?.include, undefined);
    const returned = await new Response(result.body).json() as { id: string };
    assert.equal(returned.id, "resp_compact");
    assert.equal(result.parseUsage, parseOpenAIResponsesUsage);
  });

  it("maps compact messages to input when the client omits input", async () => {
    let upstreamBody: Record<string, unknown> | undefined;
    globalThis.fetch = async (_input, init) => {
      upstreamBody = JSON.parse(String(init?.body)) as Record<string, unknown>;
      return Response.json({ id: "resp_compact", object: "response", output: [] });
    };
    await responsesCompact(
      {
        body: {
          model: "grok-4.5",
          messages: [{ role: "user", content: "summarize" }],
          conversation_id: "conv-1",
        },
        headers: {},
      },
      connection({ accessToken: "access" }),
    );
    assert.deepEqual(upstreamBody?.input, [
      { type: "message", role: "user", content: [{ type: "input_text", text: "summarize" }] },
    ]);
    assert.equal(upstreamBody?.messages, undefined);
    assert.equal(upstreamBody?.prompt_cache_key, "conv-1");
    assert.equal(upstreamBody?.conversation_id, undefined);
  });
});

function connection(credentials: unknown): ProviderConnection {
  return { connectionId: "c1", providerId: "xai-oauth", credentials };
}

describe("xai image requests", () => {
  it("maps OpenAI size and quality onto the xAI generation body", async () => {
    const seen: Array<{ url: string; body: Record<string, unknown> }> = [];
    globalThis.fetch = async (input, init) => {
      seen.push({ url: String(input), body: JSON.parse(String(init?.body)) as Record<string, unknown> });
      return Response.json({ data: [{ url: "https://images.example/out.png" }] });
    };
    const exchange = await imageGenerations(
      {
        body: {
          model: "grok-imagine-image-2.0",
          prompt: "a lighthouse",
          size: "1024x1536",
          quality: "high",
          aspect_ratio: "2:3",
        },
        headers: {},
      },
      connection({ accessToken: "access" }),
    );
    assert.equal(exchange.status, 200);
    assert.equal(seen[0]?.url, "https://api.x.ai/v1/images/generations");
    assert.deepEqual(seen[0]?.body, {
      model: "grok-imagine-image-2.0",
      prompt: "a lighthouse",
      quality: "medium",
      aspect_ratio: "2:3",
      resolution: "1.5k",
    });
  });

  it("turns one or more gateway images into xAI edit inputs and rejects a mask", async () => {
    const seen: unknown[] = [];
    globalThis.fetch = async (input, init) => {
      seen.push(JSON.parse(String(init?.body)));
      return Response.json({ data: [{ url: "https://images.example/out.png" }] });
    };
    const creds = connection({ accessToken: "access" });
    await imageEdits(
      {
        body: {
          model: "grok-imagine-image-2.0",
          prompt: "sketch",
          images: [{ b64_json: "aaaa", media_type: "image/png" }],
        },
        headers: {},
      },
      creds,
    );
    await imageEdits(
      {
        body: {
          model: "grok-imagine-image-2.0",
          prompt: "combine",
          images: [
            { url: "https://example.com/a.png" },
            { b64_json: "bbbb", media_type: "image/jpeg" },
          ],
        },
        headers: {},
      },
      creds,
    );
    const masked = await imageEdits(
      { body: { model: "grok-imagine-image-2.0", prompt: "cut", mask: { b64_json: "cccc" } }, headers: {} },
      creds,
    );
    assert.equal(seen.length, 2);
    assert.deepEqual(seen[0], {
      model: "grok-imagine-image-2.0",
      prompt: "sketch",
      image: { url: "data:image/png;base64,aaaa", type: "image_url" },
    });
    assert.deepEqual(seen[1], {
      model: "grok-imagine-image-2.0",
      prompt: "combine",
      images: [
        { url: "https://example.com/a.png", type: "image_url" },
        { url: "data:image/jpeg;base64,bbbb", type: "image_url" },
      ],
    });
    assert.equal(masked.status, 400);
    assert.deepEqual(await new Response(masked.body).json(), {
      error: { message: "mask is not supported", type: "invalid_request_error" },
    });
  });

  it("downloads a temporary URL when the client asked for base64", async () => {
    const bytes = Buffer.from([0x89, 0x50]);
    globalThis.fetch = async (input) => {
      const url = String(input);
      if (url.endsWith("/images/generations")) {
        return Response.json({ data: [{ url: "https://images.example/out.png", mime_type: "image/png" }] });
      }
      return new Response(bytes, { headers: { "content-type": "image/png" } });
    };
    const exchange = await imageGenerations(
      {
        body: { model: "grok-imagine-image", prompt: "a harbor", response_format: "b64_json", size: "1024x1024" },
        headers: {},
      },
      connection({ accessToken: "access" }),
    );
    assert.equal(exchange.status, 200);
    assert.deepEqual(await new Response(exchange.body).json(), {
      data: [{ b64_json: bytes.toString("base64"), mime_type: "image/png" }],
    });
  });
});

describe("xai video requests", () => {
  it("posts generation media as xAI urls and keeps the prompt settings", async () => {
    const seen: Array<{ url: string; authorization: string | null; body: Record<string, unknown> }> = [];
    globalThis.fetch = async (input, init) => {
      const headers = new Headers(init?.headers);
      seen.push({
        url: String(input),
        authorization: headers.get("authorization"),
        body: JSON.parse(String(init?.body)) as Record<string, unknown>,
      });
      return Response.json({ request_id: "req-1" });
    };
    const exchange = await videoGenerations(
      {
        body: {
          model: "grok-imagine-video-1.5",
          prompt: "a rocket over dunes",
          duration: 8,
          aspect_ratio: "16:9",
          resolution: "720p",
          seconds: "8",
          image: { b64_json: "aaaa", media_type: "image/png" },
          last_frame: { file_id: "file_last" },
          reference_images: [{ url: "https://example.com/hero.png", type: "image_url" }, { b64_json: "bbbb" }],
          reference_audios: [{ voice_id: "ara" }, { b64_json: "cccc", media_type: "audio/wav" }],
          keyframes: [{ timestamp_s: 4, image: { image_url: "https://example.com/mid.png" } }],
        },
        headers: {},
      },
      connection({ accessToken: "access" }),
    );
    assert.equal(exchange.status, 200);
    assert.equal(seen[0]?.url, "https://api.x.ai/v1/videos/generations");
    assert.equal(seen[0]?.authorization, "Bearer access");
    assert.deepEqual(seen[0]?.body, {
      model: "grok-imagine-video-1.5",
      prompt: "a rocket over dunes",
      duration: 8,
      aspect_ratio: "16:9",
      resolution: "720p",
      seconds: "8",
      image: { url: "data:image/png;base64,aaaa" },
      last_frame: { file_id: "file_last" },
      reference_images: [{ url: "https://example.com/hero.png" }, { url: "data:image/png;base64,bbbb" }],
      reference_audios: [{ voice_id: "ara" }, { url: "data:audio/wav;base64,cccc" }],
      keyframes: [{ timestamp_s: 4, image: { url: "https://example.com/mid.png" } }],
    });
  });

  it("posts edit and extension videos as data or remote urls", async () => {
    const seen: Array<{ url: string; body: Record<string, unknown> }> = [];
    globalThis.fetch = async (input, init) => {
      seen.push({ url: String(input), body: JSON.parse(String(init?.body)) as Record<string, unknown> });
      return Response.json({ request_id: "req-2" });
    };
    const creds = connection({ accessToken: "access" });
    await videoEdits(
      {
        body: {
          model: "grok-imagine-video",
          prompt: "add a silver necklace",
          video: { b64_json: "dddd", media_type: "video/mp4" },
        },
        headers: {},
      },
      creds,
    );
    await videoExtensions(
      {
        body: {
          model: "grok-imagine-video",
          prompt: "the camera pulls back",
          duration: 6,
          video: "https://example.com/clip.mp4",
        },
        headers: {},
      },
      creds,
    );
    assert.deepEqual(seen, [
      {
        url: "https://api.x.ai/v1/videos/edits",
        body: {
          model: "grok-imagine-video",
          prompt: "add a silver necklace",
          video: { url: "data:video/mp4;base64,dddd" },
        },
      },
      {
        url: "https://api.x.ai/v1/videos/extensions",
        body: {
          model: "grok-imagine-video",
          prompt: "the camera pulls back",
          duration: 6,
          video: { url: "https://example.com/clip.mp4" },
        },
      },
    ]);
  });

  it("polls a saved request id and rejects a missing id", async () => {
    const seen: Array<{ url: string; method: string; authorization: string | null; body: string | undefined }> = [];
    globalThis.fetch = async (input, init) => {
      const headers = new Headers(init?.headers);
      seen.push({
        url: String(input),
        method: init?.method ?? "GET",
        authorization: headers.get("authorization"),
        body: typeof init?.body === "string" ? init.body : undefined,
      });
      return Response.json({ status: "done", video: { url: "https://vidgen.x.ai/clip.mp4", duration: 8 } });
    };
    const creds = connection({ accessToken: "access" });
    const missing = await videoResult({ body: {}, headers: {} }, creds);
    const slashed = await videoResult({ body: { request_id: "a/b" }, headers: {} }, creds);
    const exchange = await videoResult({ body: { request_id: "req-1" }, headers: {} }, creds);
    assert.equal(missing.status, 400);
    assert.equal(slashed.status, 400);
    assert.equal(seen.length, 1);
    assert.equal(seen[0]?.url, "https://api.x.ai/v1/videos/req-1");
    assert.equal(seen[0]?.method, "GET");
    assert.equal(seen[0]?.authorization, "Bearer access");
    assert.equal(seen[0]?.body, undefined);
    assert.equal(exchange.status, 200);
    assert.deepEqual(await new Response(exchange.body).json(), {
      status: "done",
      video: { url: "https://vidgen.x.ai/clip.mp4", duration: 8 },
    });
  });
});

function jwt(payload: Record<string, unknown>): string {
  return `header.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.signature`;
}

describe("xai audio requests", () => {
  it("posts transcriptions as multipart and keeps the xAI model", async () => {
    const audio = Buffer.from([0x49, 0x44, 0x33, 0x00, 0xff, 0x0d, 0x0a, 0x7f]);
    const calls: Array<{
      url: string;
      authorization: string | null;
      contentType: string | null;
      accept: string | null;
      beta: string | null;
      parts: Array<{ name: string; body: Buffer }>;
    }> = [];
    globalThis.fetch = async (input, init) => {
      const headers = new Headers(init?.headers);
      const outbound = new Request(input, init);
      calls.push({
        url: String(input),
        authorization: headers.get("authorization"),
        contentType: headers.get("content-type"),
        accept: headers.get("accept"),
        beta: headers.get("openai-beta"),
        parts: decodeMultipart(
          outbound.headers.get("content-type") ?? "",
          Buffer.from(await outbound.arrayBuffer()),
        ),
      });
      return Response.json({ text: "hello", language: "en", duration: 1.25 });
    };
    const creds = connection({ accessToken: "access-token" });
    const headers = {
      authorization: "Bearer inbound-client",
      "content-type": "multipart/form-data; boundary=inbound",
      "openai-beta": "assistants=v2",
    };
    const rewritten = await audioTranscriptions(
      {
        body: {
          model: "whisper-1",
          language: "en",
          response_format: "json",
          diarize: true,
          keyterm: "Understand The Universe",
          file: { b64_json: audio.toString("base64"), media_type: "audio/wav" },
        },
        headers,
      },
      creds,
    );
    const kept = await audioTranscriptions(
      {
        body: {
          model: "grok-voice-transcribe-2.0",
          language: "",
          file: { b64_json: audio.toString("base64"), media_type: "audio/mpeg" },
        },
        headers,
      },
      creds,
    );
    assert.equal(calls[0]?.url, "https://api.x.ai/v1/stt");
    assert.equal(calls[1]?.url, "https://api.x.ai/v1/stt");
    assert.equal(calls[0]?.authorization, "Bearer access-token");
    assert.equal(calls[0]?.contentType, null);
    assert.equal(calls[0]?.accept, "application/json");
    assert.equal(calls[0]?.beta, "assistants=v2");
    assert.deepEqual(calls[0]?.parts.map((part) => part.name), ["model", "language", "file"]);
    assert.equal(calls[0]?.parts[0]?.body.toString("utf8"), "grok-voice-transcribe-2.0");
    assert.equal(calls[0]?.parts[1]?.body.toString("utf8"), "en");
    assert.deepEqual(calls[0]?.parts[2]?.body, audio);
    assert.deepEqual(calls[1]?.parts.map((part) => part.name), ["model", "file"]);
    assert.equal(calls[1]?.parts[0]?.body.toString("utf8"), "grok-voice-transcribe-2.0");
    assert.deepEqual(calls[1]?.parts[1]?.body, audio);
    assert.equal(rewritten.status, 200);
    assert.equal(kept.status, 200);
    assert.deepEqual(await new Response(rewritten.body).json(), { text: "hello", language: "en", duration: 1.25 });
  });

  it("returns plain text when response_format is text", async () => {
    globalThis.fetch = async () => Response.json({ text: "transcribed words", language: "en", duration: 1 });
    const exchange = await audioTranscriptions(
      {
        body: {
          model: "gpt-4o-transcribe",
          response_format: "text",
          file: { b64_json: Buffer.from("abc").toString("base64"), media_type: "audio/mpeg" },
        },
        headers: {},
      },
      connection({ accessToken: "access" }),
    );
    assert.equal(exchange.status, 200);
    assert.equal(exchange.headers["content-type"], "text/plain");
    assert.equal(await new Response(exchange.body).text(), "transcribed words");
  });

  it("rejects srt and vtt without calling upstream", async () => {
    let calls = 0;
    globalThis.fetch = async () => {
      calls += 1;
      return Response.json({});
    };
    const creds = connection({ accessToken: "access" });
    const srt = await audioTranscriptions(
      {
        body: {
          model: "whisper-1",
          response_format: "srt",
          file: { b64_json: "YQ==", media_type: "audio/wav" },
        },
        headers: {},
      },
      creds,
    );
    const vtt = await audioTranscriptions(
      {
        body: {
          model: "whisper-1",
          response_format: "vtt",
          file: { b64_json: "YQ==", media_type: "audio/wav" },
        },
        headers: {},
      },
      creds,
    );
    assert.equal(calls, 0);
    assert.equal(srt.status, 400);
    assert.equal(vtt.status, 400);
    assert.deepEqual(await new Response(srt.body).json(), {
      error: { message: "srt is not supported", type: "invalid_request_error" },
    });
    assert.deepEqual(await new Response(vtt.body).json(), {
      error: { message: "vtt is not supported", type: "invalid_request_error" },
    });
  });

  it("returns 400 when the transcription file is missing", async () => {
    let calls = 0;
    globalThis.fetch = async () => {
      calls += 1;
      return Response.json({});
    };
    const exchange = await audioTranscriptions(
      { body: { model: "whisper-1", file: { media_type: "audio/wav" } }, headers: {} },
      connection({ accessToken: "access" }),
    );
    assert.equal(calls, 0);
    assert.equal(exchange.status, 400);
    assert.deepEqual(await new Response(exchange.body).json(), {
      error: { message: "file is required", type: "invalid_request_error" },
    });
  });

  it("maps speech voices, clamps speed, and forwards audio bytes", async () => {
    const bytes = Buffer.from([0x49, 0x44, 0x33, 0x04, 0x00, 0xff]);
    const seen: Array<{ url: string; authorization: string | null; accept: string | null; contentType: string | null; body: Record<string, unknown> }> = [];
    globalThis.fetch = async (input, init) => {
      const headers = new Headers(init?.headers);
      seen.push({
        url: String(input),
        authorization: headers.get("authorization"),
        accept: headers.get("accept"),
        contentType: headers.get("content-type"),
        body: JSON.parse(String(init?.body)) as Record<string, unknown>,
      });
      return new Response(bytes, { headers: { "content-type": "audio/mpeg" } });
    };
    const creds = connection({ accessToken: "access-token" });
    const headers = { authorization: "Bearer inbound-client", "content-type": "text/plain" };
    const spoken = await audioSpeech(
      { body: { model: "tts-1", input: "hello there", voice: "alloy", response_format: "mp3" }, headers },
      creds,
    );
    await audioSpeech(
      { body: { model: "tts-1", input: "hello there", voice: "ara", speed: 4 }, headers },
      creds,
    );
    await audioSpeech(
      { body: { model: "tts-1", input: "hello there", voice: "eve", response_format: "wav" }, headers },
      creds,
    );
    await audioSpeech(
      { body: { model: "tts-1", input: "hello there", voice: "ara", response_format: "aac" }, headers },
      creds,
    );
    await audioSpeech(
      { body: { model: "tts-1", input: "hello there", voice: "ara", response_format: "opus" }, headers },
      creds,
    );
    await audioSpeech(
      { body: { model: "tts-1", input: "hello there", voice: "ara", response_format: "flac" }, headers },
      creds,
    );
    assert.equal(seen[0]?.url, "https://api.x.ai/v1/tts");
    assert.equal(seen[0]?.authorization, "Bearer access-token");
    assert.equal(seen[0]?.accept, "*/*");
    assert.equal(seen[0]?.contentType, "application/json");
    assert.deepEqual(seen[0]?.body, { text: "hello there", voice_id: "eve", language: "auto" });
    assert.deepEqual(seen[1]?.body, { text: "hello there", voice_id: "ara", language: "auto", speed: 1.5 });
    assert.deepEqual(seen[2]?.body, {
      text: "hello there",
      voice_id: "eve",
      language: "auto",
      output_format: { codec: "wav" },
    });
    assert.equal(seen[3]?.body.output_format, undefined);
    assert.equal(seen[4]?.body.output_format, undefined);
    assert.equal(seen[5]?.body.output_format, undefined);
    assert.equal(spoken.status, 200);
    assert.equal(spoken.headers["content-type"], "audio/mpeg");
    assert.deepEqual(Buffer.from(await new Response(spoken.body).arrayBuffer()), bytes);
  });

  it("forwards upstream audio errors without leaking the access token", async () => {
    const token = "super-secret-access-token";
    globalThis.fetch = async () => Response.json({ error: "unauthorized" }, { status: 401 });
    const stt = await audioTranscriptions(
      {
        body: {
          model: "whisper-1",
          response_format: "text",
          file: { b64_json: Buffer.from("a").toString("base64"), media_type: "audio/wav" },
        },
        headers: { authorization: `Bearer ${token}` },
      },
      connection({ accessToken: token }),
    );
    assert.equal(stt.status, 401);
    assert.equal(stt.headers["content-type"], "application/json");
    const sttBody = await new Response(stt.body).text();
    assert.equal(sttBody.includes(token), false);
    assert.deepEqual(JSON.parse(sttBody), { error: "unauthorized" });

    globalThis.fetch = async () => new Response("rate limited", { status: 429, headers: { "content-type": "text/plain" } });
    const tts = await audioSpeech(
      { body: { model: "tts-1", input: "hello there", voice: "alloy" }, headers: {} },
      connection({ accessToken: token }),
    );
    assert.equal(tts.status, 429);
    assert.equal(tts.headers["content-type"], "text/plain");
    const ttsBody = await new Response(tts.body).text();
    assert.equal(ttsBody, "rate limited");
    assert.equal(ttsBody.includes(token), false);

    globalThis.fetch = async () => {
      throw new Error("connect ECONNREFUSED");
    };
    await assert.rejects(
      audioSpeech(
        { body: { model: "tts-1", input: "hello there", voice: "ara" }, headers: {} },
        connection({ accessToken: token }),
      ),
      (error: unknown) => {
        const text = error instanceof Error ? `${error.message} ${String(error.cause ?? "")}` : String(error);
        assert.equal(text.includes(token), false);
        return true;
      },
    );
  });
});

function decodeMultipart(contentType: string, raw: Buffer): Array<{ name: string; body: Buffer }> {
  const matched = /boundary=(?:"([^"]+)"|([^;]+))/i.exec(contentType);
  const boundary = matched?.[1] ?? matched?.[2];
  assert.ok(boundary);
  return raw.toString("latin1").split(`--${boundary}`).slice(1, -1).map((piece) => {
    const chunk = piece.replace(/^\r\n/, "").replace(/\r\n$/, "");
    const splitAt = chunk.indexOf("\r\n\r\n");
    assert.ok(splitAt >= 0);
    const name = /name="([^"]*)"/.exec(chunk.slice(0, splitAt))?.[1] ?? "";
    return { name, body: Buffer.from(chunk.slice(splitAt + 4), "latin1") };
  });
}
