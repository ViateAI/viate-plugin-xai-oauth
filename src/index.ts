import { createHash, randomBytes } from "node:crypto";
import { createServer, type Server } from "node:http";
import {
  parseOpenAIChatUsage,
  parseOpenAIResponsesUsage,
  toModelList,
  type CredentialsWrite,
  type HttpExchange,
  type JsonGetRequest,
  type JsonPostRequest,
  type KeepaliveInput,
  type KeepaliveResult,
  type ModelList,
  type OAuthExchangeInput,
  type OAuthStartContext,
  type OAuthStartResult,
  type PluginContext,
  type ProviderConnection,
  type ProviderHandler,
  type SubscriptionInput,
  type SubscriptionResult,
  type SubscriptionUsage,
  type UsageParser,
  type ViatePlugin,
} from "@viateai/sdk";

const PROVIDER_ID = "xai-oauth";
const CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828";
const AUTH_BASE_URL = "https://auth.x.ai";
const AUTHORIZE_URL = `${AUTH_BASE_URL}/oauth2/authorize`;
const TOKEN_URL = `${AUTH_BASE_URL}/oauth2/token`;
const API_BASE_URL = "https://api.x.ai/v1";
const BILLING_URL = "https://cli-chat-proxy.grok.com/v1/billing?format=credits";
const USER_URL = "https://cli-chat-proxy.grok.com/v1/user?include=subscription";
const SUBSCRIPTION_DUE_MS = 10 * 60 * 1000;
const LOOPBACK_HOST = "127.0.0.1";
const LOOPBACK_PORT = 56_121;
const LOOPBACK_PATH = "/callback";
const LOOPBACK_REDIRECT_URI = `http://${LOOPBACK_HOST}:${LOOPBACK_PORT}${LOOPBACK_PATH}`;
const LOOPBACK_TIMEOUT_MS = 5 * 60 * 1_000;
const PKCE_VERIFIER_BYTES = 96;
const SCOPES = "openid profile email offline_access grok-cli:access api:access";

type XaiOauthCredentials = {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  email?: string;
  expiresAt?: string;
};

type PkceSession = {
  verifier: string;
  redirectUri: string;
};

type LoopbackState = {
  server: Server;
  timeout: NodeJS.Timeout;
};

let loopback: LoopbackState | undefined;

export const plugin: ViatePlugin = {
  id: PROVIDER_ID,
  register(ctx: PluginContext) {
    const provider: ProviderHandler & {
      audioTranscriptions: typeof audioTranscriptions;
      audioSpeech: typeof audioSpeech;
      videoGenerations: typeof videoGenerations;
      videoEdits: typeof videoEdits;
      videoExtensions: typeof videoExtensions;
      videoResult: typeof videoResult;
    } = {
      id: PROVIDER_ID,
      credentialsForm: [{ key: "token", label: "Access token", kind: "secret" }],
      parseCredentials,
      normalizeCredentials,
      startOAuth,
      exchangeOAuth,
      keepalive,
      subscription,
      chatCompletions,
      embeddings,
      listModels,
      responses,
      responsesCompact,
      imageGenerations,
      imageEdits,
      audioTranscriptions,
      audioSpeech,
      videoGenerations,
      videoEdits,
      videoExtensions,
      videoResult,
    };
    ctx.registerProvider(provider);
  },
};

export default plugin;

export function parseCredentials(text: string): unknown {
  const trimmed = text.trim();
  if (!trimmed) {
    throw new Error("xAI OAuth token is required");
  }
  if (trimmed.startsWith("{")) {
    return JSON.parse(trimmed) as unknown;
  }
  return trimmed;
}

export function normalizeCredentials(input: unknown): CredentialsWrite {
  const source = recordValue(input) ?? {};
  const accessToken = firstString(
    typeof input === "string" ? input.trim() : undefined,
    stringValue(source.access_token),
    stringValue(source.accessToken),
    stringValue(source.token),
  );
  if (!accessToken) {
    throw new Error("xAI OAuth credentials contain no access token");
  }
  const refreshToken = firstString(stringValue(source.refresh_token), stringValue(source.refreshToken));
  const idToken = firstString(stringValue(source.id_token), stringValue(source.idToken));
  const claims = decodeJwt(idToken ?? accessToken);
  const email = firstString(
    stringValue(source.email),
    stringValue(claims.email),
    stringValue(claims.preferred_username),
  );
  const expiresAt = resolveExpiresAt(source, claims);
  const credentials: XaiOauthCredentials = {
    accessToken,
    ...(refreshToken ? { refreshToken } : {}),
    ...(idToken ? { idToken } : {}),
    ...(email ? { email } : {}),
    ...(expiresAt ? { expiresAt } : {}),
  };
  return {
    credentials,
    displayLabel: email ?? `xAI …${accessToken.slice(-6)}`,
  };
}

export async function startOAuth(ctx: OAuthStartContext): Promise<OAuthStartResult> {
  const verifier = randomBytes(PKCE_VERIFIER_BYTES).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const callback = new URL(ctx.callbackUrl);
  const state = callback.searchParams.get("state") || crypto.randomUUID();
  const nonce = randomBytes(16).toString("hex");
  await listenForLoopback(ctx.callbackUrl);
  const params = new URLSearchParams({
    response_type: "code",
    client_id: CLIENT_ID,
    redirect_uri: LOOPBACK_REDIRECT_URI,
    scope: SCOPES,
    code_challenge: challenge,
    code_challenge_method: "S256",
    state,
    nonce,
    plan: "generic",
    referrer: "cli-proxy-api",
  });
  return {
    type: "authorization_url",
    authorizationUrl: `${AUTHORIZE_URL}?${params.toString()}`,
    session: { verifier, redirectUri: LOOPBACK_REDIRECT_URI } satisfies PkceSession,
  };
}

export async function exchangeOAuth(input: OAuthExchangeInput): Promise<CredentialsWrite> {
  const session = recordValue(input.session);
  const verifier = stringValue(session?.verifier);
  const redirectUri = stringValue(session?.redirectUri) ?? LOOPBACK_REDIRECT_URI;
  const code = stringValue(input.code);
  if (!verifier || !code) {
    throw new Error("xAI OAuth callback is missing code or PKCE verifier");
  }
  const response = await fetch(TOKEN_URL, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json",
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: CLIENT_ID,
      code,
      redirect_uri: redirectUri,
      code_verifier: verifier,
    }),
  });
  const data = await responseRecord(response, "xAI token exchange failed");
  return normalizeCredentials(data);
}

export async function keepalive(input: KeepaliveInput): Promise<KeepaliveResult> {
  const credentials = readCredentials(input.credentials);
  const dueMs = millisecondsUntilRefresh(credentials.expiresAt);
  if (dueMs > 0) {
    return { status: "ok", nextDueMs: dueMs };
  }
  if (!credentials.refreshToken) {
    const error = "xAI access token expired";
    input.log.warn({ status: "needs_reauth", error }, "token refresh failed");
    return { status: "needs_reauth", error };
  }
  const response = await fetch(TOKEN_URL, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json",
    },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      client_id: CLIENT_ID,
      refresh_token: credentials.refreshToken,
    }),
    signal: input.signal,
  });
  const tokenData = recordValue(await response.json().catch(() => null)) ?? {};
  if (!response.ok) {
    const detail = firstString(stringValue(tokenData.error_description), stringValue(tokenData.error));
    const status = response.status === 400 || response.status === 401 ? "needs_reauth" : "failed";
    const error = `xAI token refresh failed (${response.status})${detail ? `: ${detail}` : ""}`;
    input.log.warn({ status, error, httpStatus: response.status }, "token refresh failed");
    return { status, error };
  }
  const normalized = normalizeCredentials({
    ...credentials,
    ...tokenData,
    refresh_token: stringValue(tokenData.refresh_token) ?? credentials.refreshToken,
  });
  const refreshed = normalized.credentials as XaiOauthCredentials;
  return {
    status: "ok",
    ...normalized,
    nextDueMs: millisecondsUntilRefresh(refreshed.expiresAt),
  };
}

export async function subscription(input: SubscriptionInput): Promise<SubscriptionResult> {
  const credentials = readCredentials(input.credentials);
  let billing: Response;
  let account: Response | null = null;
  try {
    [billing, account] = await Promise.all([
      usageRequest(BILLING_URL, credentials.accessToken, input.signal),
      usageRequest(USER_URL, credentials.accessToken, input.signal).catch(() => null),
    ]);
  } catch {
    input.log.warn({ status: "failed", error: "xAI usage request failed" }, "subscription refresh failed");
    return { status: "failed", error: "xAI usage request failed" };
  }
  const denied = usageFailure(billing.status);
  if (denied) {
    const error = denied === "needs_reauth" ? "xAI session expired" : `xAI usage endpoint error (${billing.status})`;
    input.log.warn({ status: denied, error, httpStatus: billing.status }, "subscription refresh failed");
    return { status: denied, error };
  }
  const data = recordValue(await billing.json().catch(() => null));
  const config = recordValue(data?.config);
  if (!data || !config) {
    const error = "xAI usage response was not JSON";
    input.log.warn({ status: "failed", error }, "subscription refresh failed");
    return { status: "failed", error };
  }
  const resetsAt = isoTimestamp(config.currentPeriod && recordValue(config.currentPeriod)?.end)
    ?? isoTimestamp(config.billingPeriodEnd);
  const usages: SubscriptionUsage[] = [];
  const seen = new Set<string>();
  const creditPercent = typeof config.creditUsagePercent === "number" && Number.isFinite(config.creditUsagePercent)
    ? config.creditUsagePercent
    : 0;
  usages.push(percentUsage(
    claimType("credits", seen),
    creditsLabel(stringValue(recordValue(config.currentPeriod)?.type)),
    "Plan",
    creditPercent,
    resetsAt,
  ));
  const prepaid = prepaidUsage(config.prepaidBalance, seen);
  if (prepaid) usages.push(prepaid);
  for (const raw of Array.isArray(config.productUsage) ? config.productUsage : []) {
    const product = recordValue(raw);
    const name = stringValue(product?.product);
    const percent = typeof product?.usagePercent === "number" && Number.isFinite(product.usagePercent)
      ? product.usagePercent
      : undefined;
    if (!name || percent === undefined || percent < 0 || percent > 100) continue;
    const named = productName(name);
    usages.push(percentUsage(claimType(named.type, seen), named.label, "Products", percent, resetsAt));
  }
  return {
    status: "ok",
    plan: await planName(account),
    usages,
    nextDueMs: SUBSCRIPTION_DUE_MS,
  };
}

export async function chatCompletions(
  request: JsonPostRequest,
  connection: ProviderConnection,
): Promise<HttpExchange> {
  return jsonRequest("POST", "chat/completions", request, connection);
}

export async function embeddings(
  request: JsonPostRequest,
  connection: ProviderConnection,
): Promise<HttpExchange> {
  return jsonRequest("POST", "embeddings", request, connection);
}

export async function responses(
  request: JsonPostRequest,
  connection: ProviderConnection,
): Promise<HttpExchange> {
  return jsonRequest("POST", "responses", request, connection);
}

export async function responsesCompact(
  request: JsonPostRequest,
  connection: ProviderConnection,
): Promise<HttpExchange> {
  const body = toCompactRequest(recordValue(request.body) ?? {});
  return jsonRequest("POST", "responses/compact", { ...request, body }, connection);
}

export async function imageGenerations(
  request: JsonPostRequest,
  connection: ProviderConnection,
): Promise<HttpExchange> {
  return imageRequest("images/generations", request, connection, "generations");
}

export async function imageEdits(
  request: JsonPostRequest,
  connection: ProviderConnection,
): Promise<HttpExchange> {
  return imageRequest("images/edits", request, connection, "edits");
}

const STT_MODEL = "grok-voice-transcribe-2.0";
const OPENAI_PRESET_VOICES: Record<string, true> = {
  alloy: true,
  ash: true,
  ballad: true,
  coral: true,
  echo: true,
  fable: true,
  onyx: true,
  nova: true,
  sage: true,
  shimmer: true,
  verse: true,
};
const TTS_CODECS: Record<string, true> = {
  wav: true,
  pcm: true,
  mulaw: true,
  alaw: true,
};

export async function audioTranscriptions(
  request: JsonPostRequest,
  connection: ProviderConnection,
): Promise<HttpExchange> {
  const body = recordValue(request.body) ?? {};
  const format = stringValue(body.response_format)?.toLowerCase();
  if (format === "srt" || format === "vtt") {
    return imageError(400, `${format} is not supported`);
  }
  const file = recordValue(body.file);
  const encoded = stringValue(file?.b64_json);
  if (!encoded) {
    return imageError(400, "file is required");
  }
  const credentials = readCredentials(connection.credentials);
  const form = new FormData();
  const requested = stringValue(body.model);
  form.append("model", requested === STT_MODEL ? requested : STT_MODEL);
  const language = stringValue(body.language);
  if (language) form.append("language", language);
  const mediaType = stringValue(file?.media_type) ?? "application/octet-stream";
  form.append(
    "file",
    new Blob([new Uint8Array(Buffer.from(encoded, "base64"))], { type: mediaType }),
    audioFilename(mediaType),
  );
  const response = await fetch(`${API_BASE_URL}/stt`, {
    method: "POST",
    headers: audioHeaders(request.headers, credentials.accessToken, "application/json"),
    body: form,
    signal: request.signal,
  });
  if (response.ok && format === "text") {
    const parsed = recordValue(await response.json().catch(() => null));
    const transcript = typeof parsed?.text === "string" ? parsed.text : "";
    return {
      status: 200,
      headers: { "content-type": "text/plain" },
      body: new Response(transcript).body,
    };
  }
  return {
    status: response.status,
    headers: pickResponseHeaders(response.headers),
    body: response.body,
  };
}

export async function audioSpeech(
  request: JsonPostRequest,
  connection: ProviderConnection,
): Promise<HttpExchange> {
  const body = recordValue(request.body) ?? {};
  const credentials = readCredentials(connection.credentials);
  const voice = stringValue(body.voice) ?? "";
  const payload: Record<string, unknown> = {
    text: typeof body.input === "string" ? body.input : "",
    voice_id: OPENAI_PRESET_VOICES[voice.toLowerCase()] ? "eve" : voice,
    language: "auto",
  };
  if (typeof body.speed === "number" && Number.isFinite(body.speed)) {
    payload.speed = Math.min(1.5, Math.max(0.7, body.speed));
  }
  const format = stringValue(body.response_format)?.toLowerCase();
  if (format && TTS_CODECS[format]) {
    payload.output_format = { codec: format };
  }
  const response = await fetch(`${API_BASE_URL}/tts`, {
    method: "POST",
    headers: audioHeaders(request.headers, credentials.accessToken, "*/*", "application/json"),
    body: JSON.stringify(payload),
    signal: request.signal,
  });
  return {
    status: response.status,
    headers: pickResponseHeaders(response.headers),
    body: response.body,
  };
}

const VIDEO_REQUEST_ID = /^[A-Za-z0-9._:-]{1,200}$/;

export async function videoGenerations(
  request: JsonPostRequest,
  connection: ProviderConnection,
): Promise<HttpExchange> {
  return videoPost("videos/generations", request, connection);
}

export async function videoEdits(
  request: JsonPostRequest,
  connection: ProviderConnection,
): Promise<HttpExchange> {
  return videoPost("videos/edits", request, connection);
}

export async function videoExtensions(
  request: JsonPostRequest,
  connection: ProviderConnection,
): Promise<HttpExchange> {
  return videoPost("videos/extensions", request, connection);
}

export async function videoResult(
  request: JsonPostRequest,
  connection: ProviderConnection,
): Promise<HttpExchange> {
  const requestId = stringValue(recordValue(request.body)?.request_id);
  if (!requestId || !VIDEO_REQUEST_ID.test(requestId)) {
    return imageError(400, "request_id is required");
  }
  return jsonRequest("GET", `videos/${encodeURIComponent(requestId)}`, request, connection);
}

async function videoPost(
  path: "videos/generations" | "videos/edits" | "videos/extensions",
  request: JsonPostRequest,
  connection: ProviderConnection,
): Promise<HttpExchange> {
  const body = { ...(recordValue(request.body) ?? {}) };
  normalizeVideoMedia(body);
  return jsonRequest("POST", path, { ...request, body }, connection);
}

function normalizeVideoMedia(body: Record<string, unknown>): void {
  for (const key of ["image", "last_frame"] as const) {
    if (body[key] == null) {
      continue;
    }
    const image = toXaiMedia(body[key], "image/png");
    if (image) {
      body[key] = image;
    }
  }
  if (Array.isArray(body.reference_images)) {
    body.reference_images = body.reference_images.flatMap((part) => {
      const image = toXaiMedia(part, "image/png");
      return image ? [image] : [];
    });
  }
  if (Array.isArray(body.keyframes)) {
    body.keyframes = body.keyframes.map((frame) => {
      const record = recordValue(frame);
      if (!record) {
        return frame;
      }
      const image = toXaiMedia(record.image, "image/png");
      return image ? { ...record, image } : record;
    });
  }
  if (body.video != null) {
    const video = toXaiMedia(body.video, "video/mp4");
    if (video) {
      body.video = video;
    }
  }
  if (Array.isArray(body.reference_audios)) {
    body.reference_audios = body.reference_audios.flatMap((part) => {
      const clip = toXaiAudio(part);
      return clip ? [clip] : [];
    });
  }
}

function toXaiMedia(part: unknown, defaultMediaType: string): Record<string, unknown> | null {
  if (typeof part === "string" && part.trim()) {
    return { url: part.trim() };
  }
  const record = recordValue(part);
  if (!record) {
    return null;
  }
  const fileId = stringValue(record.file_id);
  if (fileId) {
    return { file_id: fileId };
  }
  const encoded = stringValue(record.b64_json);
  if (encoded) {
    const url = encoded.startsWith("data:")
      ? encoded
      : `data:${stringValue(record.media_type) ?? defaultMediaType};base64,${encoded}`;
    return { url };
  }
  const url = stringValue(record.url) ?? stringValue(record.image_url);
  return url ? { url } : null;
}

function toXaiAudio(part: unknown): Record<string, unknown> | null {
  const record = recordValue(part);
  const voiceId = stringValue(record?.voice_id);
  if (voiceId && !stringValue(record?.b64_json) && !stringValue(record?.url) && !stringValue(record?.file_id)) {
    return { voice_id: voiceId };
  }
  return toXaiMedia(part, "audio/wav");
}

export async function listModels(
  request: JsonGetRequest,
  connection: ProviderConnection,
): Promise<ModelList> {
  const exchange = await jsonRequest("GET", "models", request, connection);
  if (exchange.status >= 400) {
    throw Object.assign(new Error(`xAI models request failed (${exchange.status})`), { statusCode: 502 });
  }
  if (!exchange.body) {
    throw Object.assign(new Error("xAI models response was empty"), { statusCode: 502 });
  }
  return toModelList(JSON.parse(await new Response(exchange.body).text()) as unknown);
}

export async function closeXaiOauthLoopback(): Promise<void> {
  const current = loopback;
  loopback = undefined;
  if (!current) {
    return;
  }
  clearTimeout(current.timeout);
  await new Promise<void>((resolve, reject) => {
    current.server.close((error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}

async function jsonRequest(
  method: "GET" | "POST",
  path: string,
  request: JsonGetRequest | JsonPostRequest,
  connection: ProviderConnection,
): Promise<HttpExchange> {
  const credentials = readCredentials(connection.credentials);
  const body = method === "POST" && "body" in request ? recordValue(request.body) ?? {} : undefined;
  const streaming = body?.stream === true;
  const payload = body;
  const response = await fetch(`${API_BASE_URL}/${path}`, {
    method,
    headers: {
      ...request.headers,
      authorization: `Bearer ${credentials.accessToken}`,
      ...(method === "POST" ? { "content-type": "application/json" } : {}),
      accept: streaming ? "text/event-stream" : "application/json",
    },
    ...(payload ? { body: JSON.stringify(payload) } : {}),
    signal: request.signal,
  });
  return {
    status: response.status,
    headers: pickResponseHeaders(response.headers),
    body: response.body,
    parseUsage: parseUsageFor(path),
  };
}

const IMAGE_RATIOS: Array<[string, number]> = [
  ["1:1", 1],
  ["5:2", 2.5],
  ["2:1", 2],
  ["21:9", 21 / 9],
  ["20:9", 20 / 9],
  ["19.5:9", 19.5 / 9],
  ["16:9", 16 / 9],
  ["3:2", 1.5],
  ["4:3", 4 / 3],
  ["3:4", 3 / 4],
  ["2:3", 2 / 3],
  ["9:16", 9 / 16],
  ["9:19.5", 9 / 19.5],
  ["9:20", 9 / 20],
  ["1:2", 0.5],
];

async function imageRequest(
  path: "images/generations" | "images/edits",
  request: JsonPostRequest,
  connection: ProviderConnection,
  operation: "generations" | "edits",
): Promise<HttpExchange> {
  const body = { ...(recordValue(request.body) ?? {}) };
  if (operation === "edits" && body.mask != null && body.mask !== "") {
    return imageError(400, "mask is not supported");
  }
  applyImageSize(body);
  applyImageQuality(body);
  if (operation === "edits") {
    const images = collectImages(body);
    if (images.length === 1) {
      body.image = images[0];
    } else if (images.length > 1) {
      body.images = images;
    }
  }
  const exchange = await jsonRequest("POST", path, { ...request, body }, connection);
  if (body.response_format !== "b64_json") {
    return exchange;
  }
  return inlineBase64(exchange, request.signal);
}

function applyImageSize(body: Record<string, unknown>): void {
  const size = typeof body.size === "string" ? body.size : undefined;
  if (!size) {
    return;
  }
  delete body.size;
  const mapped = mapImageSize(size);
  if (!mapped) {
    return;
  }
  if (typeof body.aspect_ratio !== "string") {
    body.aspect_ratio = mapped.aspectRatio;
  }
  if (typeof body.resolution !== "string") {
    body.resolution = mapped.resolution;
  }
}

function mapImageSize(size: string): { aspectRatio: string; resolution: "1k" | "1.5k" | "2k" } | null {
  if (size === "auto") {
    return { aspectRatio: "auto", resolution: "1k" };
  }
  const match = /^(\d+)x(\d+)$/.exec(size);
  if (!match) {
    return null;
  }
  const width = Number(match[1]);
  const height = Number(match[2]);
  if (!width || !height) {
    return null;
  }
  const value = width / height;
  let aspectRatio = IMAGE_RATIOS[0]?.[0] ?? "1:1";
  let best = Number.POSITIVE_INFINITY;
  for (const [name, ratio] of IMAGE_RATIOS) {
    const delta = Math.abs(Math.log(value) - Math.log(ratio));
    if (delta < best) {
      best = delta;
      aspectRatio = name;
    }
  }
  const longEdge = Math.max(width, height);
  return { aspectRatio, resolution: longEdge <= 1024 ? "1k" : longEdge <= 1536 ? "1.5k" : "2k" };
}

function applyImageQuality(body: Record<string, unknown>): void {
  if (body.quality === "high" || body.quality === "xhigh" || body.quality === "max") {
    body.quality = "medium";
  }
}

function collectImages(body: Record<string, unknown>): Array<Record<string, unknown>> {
  const listed = Array.isArray(body.images) ? body.images : [];
  const parts = listed.length > 0 ? listed : body.image == null ? [] : [body.image];
  delete body.images;
  delete body.image;
  const images: Array<Record<string, unknown>> = [];
  for (const part of parts) {
    const image = toXaiImage(part);
    if (image) {
      images.push(image);
    }
  }
  return images;
}

function toXaiImage(part: unknown): Record<string, unknown> | null {
  if (typeof part === "string" && part.trim()) {
    return { url: part.trim(), type: "image_url" };
  }
  if (!part || typeof part !== "object") {
    return null;
  }
  const record = part as Record<string, unknown>;
  const fileId = stringValue(record.file_id);
  if (fileId) {
    return { file_id: fileId };
  }
  const encoded = stringValue(record.b64_json);
  if (encoded) {
    const url = encoded.startsWith("data:")
      ? encoded
      : `data:${stringValue(record.media_type) ?? "image/png"};base64,${encoded}`;
    return { url, type: "image_url" };
  }
  const url = stringValue(record.url) ?? stringValue(record.image_url);
  if (!url) {
    return null;
  }
  return { url, type: stringValue(record.type) ?? "image_url" };
}

async function inlineBase64(exchange: HttpExchange, signal: AbortSignal | undefined): Promise<HttpExchange> {
  if (exchange.status >= 400 || !exchange.body) {
    return exchange;
  }
  const text = await new Response(exchange.body).text();
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    return { ...exchange, body: new Response(text).body };
  }
  const data = recordValue(parsed)?.data;
  if (!Array.isArray(data)) {
    return { ...exchange, body: new Response(text).body };
  }
  for (const item of data) {
    const record = recordValue(item);
    if (!record || typeof record.b64_json === "string" || typeof record.url !== "string") {
      continue;
    }
    const response = await fetch(record.url, { signal });
    if (!response.ok) {
      return imageError(502, "failed to read generated image");
    }
    record.b64_json = Buffer.from(await response.arrayBuffer()).toString("base64");
    delete record.url;
  }
  return {
    ...exchange,
    headers: { ...exchange.headers, "content-type": "application/json" },
    body: new Response(JSON.stringify(parsed)).body,
  };
}

function imageError(status: number, message: string): HttpExchange {
  return {
    status,
    headers: { "content-type": "application/json" },
    body: new Response(JSON.stringify({ error: { message, type: "invalid_request_error" } })).body,
  };
}

function audioFilename(mediaType: string): string {
  const subtype = mediaType.split("/")[1]?.split(";")[0]?.trim().toLowerCase() ?? "";
  const extension = /^[a-z0-9.+-]+$/.test(subtype) ? subtype : "bin";
  return `audio.${extension}`;
}

function audioHeaders(
  inbound: Record<string, string>,
  accessToken: string,
  accept: string,
  contentType?: string,
): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(inbound)) {
    const lower = name.toLowerCase();
    if (lower === "authorization" || lower === "content-type" || lower === "accept") continue;
    headers[name] = value;
  }
  headers.authorization = `Bearer ${accessToken}`;
  headers.accept = accept;
  if (contentType) headers["content-type"] = contentType;
  return headers;
}

async function listenForLoopback(callbackUrl: string): Promise<void> {
  await closeXaiOauthLoopback();
  const server = createServer((req, res) => {
    const requestUrl = new URL(req.url ?? "/", LOOPBACK_REDIRECT_URI);
    if (requestUrl.pathname !== LOOPBACK_PATH) {
      res.writeHead(404).end();
      return;
    }
    const next = new URL(callbackUrl);
    const code = requestUrl.searchParams.get("code");
    const state = requestUrl.searchParams.get("state") ?? next.searchParams.get("state");
    if (code) next.searchParams.set("code", code);
    if (state) next.searchParams.set("state", state);
    res.writeHead(302, { location: next.toString() }).end();
    void closeXaiOauthLoopback();
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", (error) => {
      reject(
        error && typeof error === "object" && "code" in error && error.code === "EADDRINUSE"
          ? new Error(`xAI OAuth loopback port ${LOOPBACK_PORT} is already in use`)
          : error,
      );
    });
    server.listen(LOOPBACK_PORT, LOOPBACK_HOST, () => resolve());
  });
  const timeout = setTimeout(() => {
    void closeXaiOauthLoopback();
  }, LOOPBACK_TIMEOUT_MS);
  timeout.unref();
  loopback = { server, timeout };
}

function pickResponseHeaders(headers: Headers): Record<string, string> {
  const picked: Record<string, string> = {};
  for (const name of ["content-type", "cache-control"]) {
    const value = headers.get(name);
    if (value) picked[name] = value;
  }
  return picked;
}

function parseUsageFor(path: string): UsageParser | undefined {
  if (path === "chat/completions") {
    return parseOpenAIChatUsage;
  }
  if (path === "responses" || path === "responses/compact") {
    return parseOpenAIResponsesUsage;
  }
  return undefined;
}

function readCredentials(input: unknown): XaiOauthCredentials {
  return normalizeCredentials(input).credentials as XaiOauthCredentials;
}

function usageRequest(url: string, token: string, signal: AbortSignal): Promise<Response> {
  return fetch(url, {
    method: "GET",
    redirect: "manual",
    headers: {
      authorization: `Bearer ${token}`,
      accept: "application/json",
      "user-agent": "viate-xai-usage/1.0",
      "x-grok-client-mode": "cli",
    },
    signal,
  });
}

function usageFailure(status: number): "needs_reauth" | "failed" | null {
  if (status === 0 || (status >= 300 && status < 400) || status === 401 || status === 403) return "needs_reauth";
  if (status < 200 || status >= 300) return "failed";
  return null;
}

async function planName(account: Response | null): Promise<string> {
  if (!account || usageFailure(account.status)) return "xAI";
  const tier = stringValue(recordValue(await account.json().catch(() => null))?.subscriptionTier);
  return tier ? tier.slice(0, 120) : "xAI";
}

function percentUsage(
  type: string,
  label: string,
  group: string,
  raw: number,
  resetsAt: string | undefined,
): SubscriptionUsage {
  const used = Math.round(Math.min(100, Math.max(0, raw)) * 100) / 100;
  return {
    type,
    label,
    group,
    unit: "percent",
    used,
    limit: 100,
    remaining: Math.round((100 - used) * 100) / 100,
    ...(resetsAt ? { resetsAt } : {}),
  };
}

function prepaidUsage(value: unknown, seen: Set<string>): SubscriptionUsage | undefined {
  const cents = recordValue(value)?.val;
  if (typeof cents !== "number" || !Number.isInteger(cents) || cents <= 0) return undefined;
  return {
    type: claimType("prepaid", seen),
    label: "Prepaid",
    group: "Plan",
    unit: "currency",
    currency: "USD",
    used: null,
    limit: null,
    remaining: cents / 100,
  };
}

function productName(value: string): { type: string; label: string } {
  const label = value.trim().slice(0, 120);
  const compact = label.toLowerCase().replace(/[^a-z0-9]+/g, "");
  if (compact === "grokbuild" || compact === "productgrokbuild") {
    return { type: "product:grok_build", label: "Grok Build" };
  }
  const slug = label.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 60);
  return { type: `product:${slug || "unknown"}`, label };
}

function creditsLabel(periodType: string | undefined): string {
  const type = (periodType ?? "").toUpperCase();
  if (type.includes("MONTH")) return "Monthly credits";
  if (type.includes("DAY")) return "Daily credits";
  if (type.includes("WEEK") || type.length === 0) return "Weekly credits";
  return "Credits";
}

function claimType(base: string, seen: Set<string>): string {
  let type = base;
  let suffix = 2;
  while (seen.has(type)) type = `${base}:${suffix++}`;
  seen.add(type);
  return type;
}

function isoTimestamp(value: unknown): string | undefined {
  if (typeof value !== "string" || !value.trim()) return undefined;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? undefined : new Date(parsed).toISOString();
}

function resolveExpiresAt(source: Record<string, unknown>, claims: Record<string, unknown>): string | undefined {
  const explicit = firstString(stringValue(source.expires_at), stringValue(source.expiresAt));
  if (explicit) return explicit;
  if (typeof source.expires_in === "number" && Number.isFinite(source.expires_in) && source.expires_in > 0) {
    return new Date(Date.now() + source.expires_in * 1_000).toISOString();
  }
  if (typeof claims.exp === "number") {
    return new Date(claims.exp * 1_000).toISOString();
  }
  return undefined;
}

function recordValue(input: unknown): Record<string, unknown> | undefined {
  return input && typeof input === "object" && !Array.isArray(input)
    ? input as Record<string, unknown>
    : undefined;
}

function toCompactRequest(body: Record<string, unknown>): Record<string, unknown> {
  const compact = { ...body };
  if (!compact.input && Array.isArray(compact.messages)) {
    compact.input = compact.messages.map((raw) => {
      const message = recordValue(raw) ?? {};
      const role = stringValue(message.role) ?? "user";
      const content = typeof message.content === "string"
        ? [{ type: "input_text", text: message.content }]
        : Array.isArray(message.content)
          ? message.content.map((part) => {
              const record = recordValue(part);
              if (record?.type === "text") {
                return { type: "input_text", text: record.text };
              }
              return part;
            })
          : message.content;
      return {
        type: "message",
        role,
        ...(typeof message.phase === "string" ? { phase: message.phase } : {}),
        content,
      };
    });
  }
  if (!compact.prompt_cache_key) {
    const cacheKey = firstString(
      stringValue(compact.session_id),
      stringValue(compact.conversation_id),
    );
    if (cacheKey) {
      compact.prompt_cache_key = cacheKey;
    }
  }
  delete compact.stream;
  delete compact.stream_options;
  delete compact.client_metadata;
  delete compact.include;
  delete compact.store;
  delete compact.messages;
  delete compact.prompt;
  delete compact.session_id;
  delete compact.conversation_id;
  return compact;
}

function stringValue(input: unknown): string | undefined {
  return typeof input === "string" && input.trim() ? input.trim() : undefined;
}

function firstString(...values: Array<string | undefined>): string | undefined {
  return values.find(Boolean);
}

function decodeJwt(token: string): Record<string, unknown> {
  try {
    const encoded = token.split(".")[1];
    if (!encoded) return {};
    return recordValue(JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"))) ?? {};
  } catch {
    return {};
  }
}

function millisecondsUntilRefresh(expiresAt: string | undefined): number {
  if (!expiresAt) return 60 * 60 * 1_000;
  return Math.max(0, Date.parse(expiresAt) - Date.now() - 5 * 60 * 1_000);
}

async function responseRecord(response: Response, prefix: string): Promise<Record<string, unknown>> {
  const data = recordValue(await response.json().catch(() => null)) ?? {};
  if (!response.ok) {
    const detail = firstString(stringValue(data.error_description), stringValue(data.error));
    throw new Error(`${prefix} (${response.status})${detail ? `: ${detail}` : ""}`);
  }
  return data;
}
