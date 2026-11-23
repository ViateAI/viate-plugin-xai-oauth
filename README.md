# @viateai/plugin-xai-oauth

Viate provider for the xAI API using a Grok CLI OAuth token. Provider id: `xai-oauth`.

This is separate from `@viateai/plugin-grok`, which sends chat to `https://cli-chat-proxy.grok.com/v1`. `xai-oauth` sends inference to `https://api.x.ai/v1`.

Supported calls: chat completions, responses, responses compact, embeddings, models, image generations, image edits, audio transcriptions, audio speech, and video generations, edits, extensions, and result. Bodies are forwarded. Image sizes and quality are mapped onto xAI's aspect ratio and resolution fields. Video media parts are rewritten into the xAI media shape.

Subscription reads `https://cli-chat-proxy.grok.com/v1/billing?format=credits` and `https://cli-chat-proxy.grok.com/v1/user?include=subscription`. Those are not on `api.x.ai`.

## Connection

Authorization-code PKCE uses the public Grok CLI client `b1a00492-073a-47ea-816f-4c329264a828` on `https://auth.x.ai`. There is no client secret. Scopes are `openid profile email offline_access grok-cli:access api:access`.

The registered redirect is `http://127.0.0.1:56121/callback`, on the computer running the gateway. The plugin listens there and redirects `code` and `state` to the admin callback. If port `56121` is already in use, login fails. The listener closes after the redirect, or after five minutes.

A pasted credential also works. A raw string is the access token. JSON accepts `access_token` / `accessToken` and `refresh_token` / `refreshToken`.

`keepalive` refreshes the access token five minutes before `expiresAt`. Without `expiresAt`, the next check is one hour later.

## Install

This package is not published to npm. Clone the repository, compile it, and install that directory. `viate.entry` is `dist/index.js`, and `dist/` is not in git. The installer runs with `ignore-scripts=true`, so it will not compile the package for you.

Node.js >= 24. pnpm 12.16.1, pinned by `packageManager`.

```bash
git clone https://github.com/ViateAI/viate-plugin-xai-oauth.git
cd viate-plugin-xai-oauth
pnpm install
pnpm build
viate plugin add "$PWD"
```

`$PWD` is passed to `pnpm add` by the `viate` process. From the admin plugin source field, use the same directory as an absolute path that process can read.

`@viateai/sdk` is a peer of `1.0.1`; the gateway removes it at install and loads its own copy. `plugin add` stages a pending workspace. Restart the gateway to load it.

To install a newer checkout, pull, run `pnpm install` and `pnpm build` again, then `viate plugin add "$PWD"` again, and restart.

Plugins run in-process. Install only packages you trust. See [Viate](https://github.com/ViateAI/viate).

## Development

```bash
pnpm install
pnpm typecheck
pnpm test
pnpm build
```

Release Please on `main` owns the version and changelog. Do not edit either by hand.

MIT. See [LICENSE](LICENSE).
