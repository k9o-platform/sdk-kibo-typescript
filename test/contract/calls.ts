/**
 * Every `vault.secrets.*` and `vault.zkDeks.*` method of the Kibo vault client, with representative arguments.
 * `expect*` pin what the SDK must put on the wire beyond what the OpenAPI can say (the route declares an op-multiplexed
 * body as a union, so the OpenAPI alone cannot catch a wrong `move` body).
 */
import type { KiboClient } from "../../src/index.ts";

export type KiboCall = {
  id: string;
  call: (c: KiboClient) => Promise<unknown>;
  /** Query parameters the gateway handler reads although its OpenAPI entry omits them (vault-forward.ts reads `region`). */
  extraQuery?: string[];
  /** The exact request(s) the call must send, in order: `METHOD path` plus the `op` query value, if any. */
  expectRoutes: { route: string; op?: string; header?: string; body?: unknown }[];
};

const SECRET = "/@demo-app/vault/secrets/db%2Fpw";

export const CALLS: KiboCall[] = [
  { id: "secrets.list", call: (c) => c.vault.secrets.list({ prefix: "db/", limit: 10 }), expectRoutes: [{ route: "GET /@demo-app/vault/secrets" }] },
  // get: the secret route answers a plain GET only as a reveal (401 without the challenge), so metadata comes from the list route.
  { id: "secrets.get", call: (c) => c.vault.secrets.get("db/pw"), expectRoutes: [{ route: "GET /@demo-app/vault/secrets" }] },
  { id: "secrets.get (legacy region arg)", extraQuery: ["region"], call: (c) => c.vault.secrets.get("db/pw", { region: "de01" }), expectRoutes: [{ route: "GET /@demo-app/vault/secrets" }] },
  { id: "secrets.create", call: (c) => c.vault.secrets.create({ name: "db/pw", value: "x" }), expectRoutes: [{ route: `POST ${SECRET}`, body: { value: "eA==" } }] },
  { id: "secrets.create (region)", extraQuery: ["region"], call: (c) => c.vault.secrets.create({ name: "db/pw", value: "x", region: "de01", visibility: { kind: "private" }, metadata: { a: "b" } }), expectRoutes: [{ route: `POST ${SECRET}`, body: { value: "eA==", visibility: { kind: "private" }, metadata: { a: "b" } } }] },
  { id: "secrets.revealChallenge", call: (c) => c.vault.secrets.revealChallenge("db/pw"), expectRoutes: [{ route: `POST ${SECRET}`, op: "reveal-challenge" }] },
  { id: "secrets.revealChallenge (reason)", call: (c) => c.vault.secrets.revealChallenge("db/pw", { reason: "rotation" }), expectRoutes: [{ route: `POST ${SECRET}`, op: "reveal-challenge", body: { reason: "rotation" } }] },
  { id: "secrets.reveal", call: (c) => c.vault.secrets.reveal("db/pw", { challenge: "rvc_1" }), expectRoutes: [{ route: `GET ${SECRET}`, header: "rvc_1" }] },
  { id: "secrets.update", call: (c) => c.vault.secrets.update("db/pw", { value: "y", metadata: { a: "b" } }), expectRoutes: [{ route: `PUT ${SECRET}`, body: { value: "eQ==", metadata: { a: "b" } } }] },
  { id: "secrets.update (region)", extraQuery: ["region"], call: (c) => c.vault.secrets.update("db/pw", { region: "de01", value: "y" }), expectRoutes: [{ route: `PUT ${SECRET}`, body: { value: "eQ==" } }] },
  { id: "secrets.rotate", call: (c) => c.vault.secrets.rotate("db/pw"), expectRoutes: [{ route: `POST ${SECRET}`, op: "rotate" }] },
  { id: "secrets.move", call: (c) => c.vault.secrets.move("db/pw", { newPath: "db/pw2" }), expectRoutes: [{ route: `POST ${SECRET}`, op: "move", body: { newPath: "db/pw2" } }] },
  { id: "secrets.delete", call: (c) => c.vault.secrets.delete("db/pw"), expectRoutes: [{ route: `DELETE ${SECRET}` }] },
  { id: "zkDeks.store", call: (c) => c.vault.zkDeks.store({ envelope: "AAEC", provider: "aws-kms", keyVersionRef: "arn:aws:kms:eu-central-1:1:key/k" }), expectRoutes: [{ route: "POST /@demo-app/vault/zk-deks", body: { envelope: "AAEC", provider: "aws-kms", keyVersionRef: "arn:aws:kms:eu-central-1:1:key/k" } }] },
  { id: "zkDeks.fetch", call: (c) => c.vault.zkDeks.fetch("zkdek_abc"), expectRoutes: [{ route: "GET /@demo-app/vault/zk-deks/zkdek_abc" }] },
];
