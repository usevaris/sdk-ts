import { afterEach, describe, expect, it, vi } from "vitest";
import { Varis, VarisKeyFetchError, type VarisPublicKey } from "../src/index.js";
import { VARIS_SIGNING_KEYS_URL } from "../src/constants.js";

interface TestKey {
  kid: string;
  privateKey: CryptoKey;
  publicKey: VarisPublicKey;
}

async function makeKey(kid: string): Promise<TestKey> {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const spki = new Uint8Array(
    await crypto.subtle.exportKey("spki", pair.publicKey),
  );
  const base64 = btoa(String.fromCharCode(...spki));
  const pem = `-----BEGIN PUBLIC KEY-----\n${base64}\n-----END PUBLIC KEY-----\n`;
  return {
    kid,
    privateKey: pair.privateKey,
    publicKey: { kid, public_key_pem: pem },
  };
}

/**
 * Signs the way the gateway does: Ed25519 over UTF-8
 * `${timestamp}.${invocationId}.${method}.${pathAndQuery}.${rawBody}`, with
 * an empty body for GET. `legacy` signs the string from before the
 * invocation ID, `${timestamp}.${method}.${pathAndQuery}.${rawBody}`.
 * `deliverTo` and `deliverAs` send the signed request somewhere else, the
 * way a replayed request would arrive.
 */
async function signedRequest(
  key: TestKey,
  body: string,
  options: {
    timestamp?: number;
    headers?: Record<string, string | null>;
    method?: "GET" | "POST";
    url?: string;
    deliverTo?: string;
    deliverAs?: "GET" | "POST";
    invocationId?: string;
    legacy?: boolean;
  } = {},
): Promise<Request> {
  const method = options.method ?? "POST";
  const url = options.url ?? "https://provider.example.com/weather";
  const rawBody = method === "GET" ? "" : body;
  const { pathname, search } = new URL(url);
  const timestamp = String(
    options.timestamp ?? Math.floor(Date.now() / 1000),
  );
  const invocationId = options.invocationId ?? INVOCATION_ID;
  const signedText = options.legacy
    ? `${timestamp}.${method}.${pathname}${search}.${rawBody}`
    : `${timestamp}.${invocationId}.${method}.${pathname}${search}.${rawBody}`;
  const signature = new Uint8Array(
    await crypto.subtle.sign(
      { name: "Ed25519" },
      key.privateKey,
      new TextEncoder().encode(signedText),
    ),
  );
  const headers: Record<string, string | null> = {
    ...(method === "POST" && { "content-type": "application/json" }),
    "x-varis-invocation-id": invocationId,
    "x-varis-timestamp": timestamp,
    "x-varis-signature": btoa(String.fromCharCode(...signature)),
    "x-varis-key-id": key.kid,
    ...options.headers,
  };
  const sentMethod = options.deliverAs ?? method;
  return new Request(options.deliverTo ?? url, {
    method: sentMethod,
    body: sentMethod === "GET" ? undefined : rawBody,
    headers: Object.fromEntries(
      Object.entries(headers).filter(
        (entry): entry is [string, string] => entry[1] !== null,
      ),
    ),
  });
}

/** Stubs fetch to serve the given key lists, one per call. The last one repeats. */
function serveKeys(...responses: VarisPublicKey[][]) {
  const fetchMock = vi.fn(async (_url: string | URL | Request, _init?: RequestInit) => {
    const keys = responses.length > 1 ? responses.shift()! : responses[0]!;
    return Response.json({ keys });
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

const BODY = JSON.stringify({ city: "Lagos", note: "café" });
const INVOCATION_ID = "var_invk_00000000000001";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("Varis.requests.verify", () => {
  it("accepts a correctly signed request", async () => {
    const key = await makeKey("k1");
    const fetchMock = serveKeys([key.publicKey]);

    const varis = new Varis();
    expect(await varis.requests.verify(await signedRequest(key, BODY))).toBe(true);
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(fetchMock.mock.calls[0]![0]).toBe(VARIS_SIGNING_KEYS_URL);
  });

  it("caches keys across requests", async () => {
    const key = await makeKey("k1");
    const fetchMock = serveKeys([key.publicKey]);
    const varis = new Varis();

    await varis.requests.verify(await signedRequest(key, BODY));
    await varis.requests.verify(await signedRequest(key, BODY));

    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("uses keysUrl when set", async () => {
    const key = await makeKey("k1");
    const fetchMock = serveKeys([key.publicKey]);
    const keysUrl = "http://localhost:3000/.well-known/varis-signing-keys";

    await new Varis({ keysUrl }).requests.verify(await signedRequest(key, BODY));

    expect(fetchMock.mock.calls[0]![0]).toBe(keysUrl);
  });

  it("bounds the key fetch and refuses a redirect", async () => {
    const key = await makeKey("k1");
    const fetchMock = serveKeys([key.publicKey]);

    await new Varis().requests.verify(await signedRequest(key, BODY));

    const init = fetchMock.mock.calls[0]![1];
    expect(init?.redirect).toBe("error");
    expect(init?.signal).toBeInstanceOf(AbortSignal);
    expect(init?.signal?.aborted).toBe(false);
  });

  it("rejects a tampered body", async () => {
    const key = await makeKey("k1");
    serveKeys([key.publicKey]);
    const signed = await signedRequest(key, BODY);
    const tampered = new Request(signed.url, {
      method: "POST",
      headers: signed.headers,
      body: BODY.replace("Lagos", "Abuja"),
    });

    expect(await new Varis().requests.verify(tampered)).toBe(false);
  });

  it("accepts a signed GET with its input in the query string", async () => {
    const key = await makeKey("k1");
    serveKeys([key.publicKey]);
    // Form-encoded the way the gateway sends it: a space is +.
    const request = await signedRequest(key, "", {
      method: "GET",
      url: "https://provider.example.com/weather?city=Port+Harcourt&units=metric",
    });

    expect(await new Varis().requests.verify(request)).toBe(true);
  });

  it("rejects a GET replayed with a changed query", async () => {
    const key = await makeKey("k1");
    serveKeys([key.publicKey]);
    const request = await signedRequest(key, "", {
      method: "GET",
      url: "https://provider.example.com/weather?city=Lagos",
      deliverTo: "https://provider.example.com/weather?city=Abuja",
    });

    expect(await new Varis().requests.verify(request)).toBe(false);
  });

  it("rejects a request replayed to another path", async () => {
    const key = await makeKey("k1");
    serveKeys([key.publicKey]);
    const request = await signedRequest(key, BODY, {
      deliverTo: "https://provider.example.com/admin",
    });

    expect(await new Varis().requests.verify(request)).toBe(false);
  });

  it("rejects a request replayed with another method", async () => {
    const key = await makeKey("k1");
    serveKeys([key.publicKey]);
    const request = await signedRequest(key, "", {
      method: "GET",
      url: "https://provider.example.com/weather",
      deliverAs: "POST",
    });

    expect(await new Varis().requests.verify(request)).toBe(false);
  });

  it("accepts a request whose host was rewritten by a proxy", async () => {
    const key = await makeKey("k1");
    serveKeys([key.publicKey]);
    const request = await signedRequest(key, BODY, {
      url: "https://provider.example.com/weather",
      deliverTo: "http://internal-host:8080/weather",
    });

    expect(await new Varis().requests.verify(request)).toBe(true);
  });

  describe("the signed string", () => {
    it("rejects a request replayed under another invocation ID", async () => {
      const key = await makeKey("k1");
      serveKeys([key.publicKey]);
      const request = await signedRequest(key, BODY, {
        headers: { "x-varis-invocation-id": "var_invk_00000000000002" },
      });

      expect(await new Varis().requests.verify(request)).toBe(false);
    });

    it("falls back to the string from before the invocation ID", async () => {
      const key = await makeKey("k1");
      serveKeys([key.publicKey]);
      const request = await signedRequest(key, BODY, { legacy: true });

      expect(await new Varis().requests.verify(request)).toBe(true);
    });

    it("checks only the old string when there's no invocation ID", async () => {
      const key = await makeKey("k1");
      serveKeys([key.publicKey]);
      const legacy = await signedRequest(key, BODY, {
        legacy: true,
        headers: { "x-varis-invocation-id": null },
      });
      const current = await signedRequest(key, BODY, {
        headers: { "x-varis-invocation-id": null },
      });

      expect(await new Varis().requests.verify(legacy)).toBe(true);
      expect(await new Varis().requests.verify(current)).toBe(false);
    });
  });

  describe("a Node.js req", () => {
    /**
     * The Express req for a signed Web request, after express.json(). Inside
     * a router mounted at `mountPath`, Express strips it from `url` only.
     */
    async function expressRequest(signed: Request, mountPath = "") {
      const { pathname, search } = new URL(signed.url);
      const text = await signed.text();
      return {
        method: signed.method,
        url: `${pathname.slice(mountPath.length)}${search}`,
        originalUrl: `${pathname}${search}`,
        headers: Object.fromEntries(signed.headers),
        body: text ? JSON.parse(text) : {},
      };
    }

    it("accepts a signed POST after express.json()", async () => {
      const key = await makeKey("k1");
      serveKeys([key.publicKey]);
      const body = JSON.stringify({ a: { b: [1, "é", { c: null }] }, n: -1.5 });
      const req = await expressRequest(await signedRequest(key, body));

      expect(await new Varis().requests.verify(req)).toBe(true);
    });

    it("accepts a signed GET inside a mounted router", async () => {
      const key = await makeKey("k1");
      serveKeys([key.publicKey]);
      const signed = await signedRequest(key, "", {
        method: "GET",
        url: "https://provider.example.com/v1/weather?city=Port+Harcourt",
      });

      const req = await expressRequest(signed, "/v1");
      expect(req.url).toBe("/weather?city=Port+Harcourt");
      expect(await new Varis().requests.verify(req)).toBe(true);
    });

    it("rejects a tampered body", async () => {
      const key = await makeKey("k1");
      serveKeys([key.publicKey]);
      const req = await expressRequest(await signedRequest(key, BODY));
      req.body.city = "Abuja";

      expect(await new Varis().requests.verify(req)).toBe(false);
    });

    it("returns false for an unsigned request without a body parser", async () => {
      const req = { method: "POST", url: "/render", headers: {} };

      expect(await new Varis().requests.verify(req)).toBe(false);
    });
  });

  it("rejects a stale timestamp", async () => {
    const key = await makeKey("k1");
    serveKeys([key.publicKey]);
    const timestamp = Math.floor(Date.now() / 1000) - 301;

    const request = await signedRequest(key, BODY, { timestamp });
    expect(await new Varis().requests.verify(request)).toBe(false);
  });

  it("rejects a future timestamp", async () => {
    const key = await makeKey("k1");
    serveKeys([key.publicKey]);
    const timestamp = Math.floor(Date.now() / 1000) + 301;

    const request = await signedRequest(key, BODY, { timestamp });
    expect(await new Varis().requests.verify(request)).toBe(false);
  });

  it("honors maxClockSkewSeconds", async () => {
    const key = await makeKey("k1");
    serveKeys([key.publicKey]);
    const timestamp = Math.floor(Date.now() / 1000) - 120;

    const varis = new Varis({ maxClockSkewSeconds: 60 });
    expect(
      await varis.requests.verify(await signedRequest(key, BODY, { timestamp })),
    ).toBe(false);
  });

  it("refetches once for an unknown key ID and accepts it when it appears", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const k1 = await makeKey("k1");
    const k2 = await makeKey("k2");
    const fetchMock = serveKeys([k1.publicKey], [k1.publicKey, k2.publicKey]);
    const varis = new Varis();

    expect(await varis.requests.verify(await signedRequest(k1, BODY))).toBe(true);
    vi.advanceTimersByTime(61_000);
    expect(await varis.requests.verify(await signedRequest(k2, BODY))).toBe(true);

    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("rejects an unknown key ID that never appears, refetching at most once a minute", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const k1 = await makeKey("k1");
    const rogue = await makeKey("rogue");
    const fetchMock = serveKeys([k1.publicKey]);
    const varis = new Varis();

    expect(await varis.requests.verify(await signedRequest(k1, BODY))).toBe(true);
    vi.advanceTimersByTime(61_000);
    expect(await varis.requests.verify(await signedRequest(rogue, BODY))).toBe(
      false,
    );
    expect(await varis.requests.verify(await signedRequest(rogue, BODY))).toBe(
      false,
    );

    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("rejects requests with missing headers", async () => {
    const key = await makeKey("k1");
    serveKeys([key.publicKey]);
    const varis = new Varis();

    for (const name of ["x-varis-signature", "x-varis-timestamp"]) {
      const request = await signedRequest(key, BODY, {
        headers: { [name]: null },
      });
      expect(await varis.requests.verify(request)).toBe(false);
    }
  });

  it("uses the only known key when the key ID is missing", async () => {
    const key = await makeKey("k1");
    serveKeys([key.publicKey]);

    const request = await signedRequest(key, BODY, {
      headers: { "x-varis-key-id": null },
    });
    expect(await new Varis().requests.verify(request)).toBe(true);
  });

  it("rejects a missing key ID when more than one key is known", async () => {
    const k1 = await makeKey("k1");
    const k2 = await makeKey("k2");
    serveKeys([k1.publicKey, k2.publicKey]);

    const request = await signedRequest(k1, BODY, {
      headers: { "x-varis-key-id": null },
    });
    expect(await new Varis().requests.verify(request)).toBe(false);
  });

  it("rejects a malformed signature", async () => {
    const key = await makeKey("k1");
    serveKeys([key.publicKey]);
    const varis = new Varis();

    for (const signature of ["not base64!", btoa("too short")]) {
      const request = await signedRequest(key, BODY, {
        headers: { "x-varis-signature": signature },
      });
      expect(await varis.requests.verify(request)).toBe(false);
    }
  });

  it("leaves the body readable", async () => {
    const key = await makeKey("k1");
    serveKeys([key.publicKey]);
    const request = await signedRequest(key, BODY);

    expect(await new Varis().requests.verify(request)).toBe(true);
    expect(await request.json()).toEqual(JSON.parse(BODY));
  });

  it("makes no network request when publicKeys is set", async () => {
    const key = await makeKey("k1");
    const other = await makeKey("k2");
    const fetchMock = serveKeys([]);
    const varis = new Varis({ publicKeys: [key.publicKey] });

    expect(await varis.requests.verify(await signedRequest(key, BODY))).toBe(true);
    expect(await varis.requests.verify(await signedRequest(other, BODY))).toBe(
      false,
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("throws VarisKeyFetchError when the keys can't be fetched", async () => {
    const key = await makeKey("k1");
    const request = await signedRequest(key, BODY);

    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("unavailable", { status: 503 })),
    );
    await expect(new Varis().requests.verify(request.clone())).rejects.toThrow(
      VarisKeyFetchError,
    );

    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new TypeError("fetch failed");
      }),
    );
    await expect(new Varis().requests.verify(request)).rejects.toThrow(
      VarisKeyFetchError,
    );
  });
});

describe("varis test requests", () => {
  const LOOPBACK = "http://127.0.0.1:47823/varis-test-key";
  const TEST_ID = "var_tst_req_4f0c2b8e";

  /**
   * Stands in for the CLI's loopback listener: answers with the throwaway
   * key only for `servedId`. Everything else fails, as a closed port would.
   */
  function cliListening(key: TestKey, servedId = TEST_ID) {
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      const url = new URL(String(input));
      if (`${url.origin}${url.pathname}` !== LOOPBACK) {
        throw new TypeError("fetch failed");
      }
      if (url.searchParams.get("request_id") !== servedId) {
        return new Response("unknown request", { status: 404 });
      }
      return Response.json(key.publicKey);
    });
    vi.stubGlobal("fetch", fetchMock);
    return fetchMock;
  }

  const testHeaders = (id = TEST_ID) => ({ "x-varis-request-id": id });

  it("accepts a test request when the CLI on this machine vouches for it", async () => {
    const key = await makeKey("varis-test");
    const fetchMock = cliListening(key);
    const request = await signedRequest(key, BODY, { headers: testHeaders() });

    expect(await new Varis().requests.verify(request)).toBe(true);
    expect(String(fetchMock.mock.calls[0]![0])).toBe(
      `${LOOPBACK}?request_id=${TEST_ID}`,
    );
  });

  it("rejects a test request when nothing listens, as in production, without throwing", async () => {
    const key = await makeKey("varis-test");
    vi.stubGlobal("fetch", vi.fn(async () => {
      throw new TypeError("connect ECONNREFUSED 127.0.0.1:47823");
    }));
    const request = await signedRequest(key, BODY, { headers: testHeaders() });

    await expect(new Varis().requests.verify(request)).resolves.toBe(false);
  });

  it("rejects a tampered test request", async () => {
    const key = await makeKey("varis-test");
    cliListening(key);
    const signed = await signedRequest(key, BODY, { headers: testHeaders() });
    const tampered = new Request(signed.url, {
      method: "POST",
      headers: signed.headers,
      body: BODY.replace("Lagos", "Abuja"),
    });

    expect(await new Varis().requests.verify(tampered)).toBe(false);
  });

  it("rejects a test signature the CLI didn't make", async () => {
    const served = await makeKey("varis-test");
    const forger = await makeKey("varis-test");
    cliListening(served);
    const request = await signedRequest(forger, BODY, { headers: testHeaders() });

    expect(await new Varis().requests.verify(request)).toBe(false);
  });

  it("rejects a test key without a test request ID", async () => {
    const key = await makeKey("varis-test");
    const fetchMock = cliListening(key);
    const request = await signedRequest(key, BODY, {
      headers: { "x-varis-request-id": "var_req_4f0c2b8e" },
    });

    expect(await new Varis().requests.verify(request)).toBe(false);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects a test request ID under a production key", async () => {
    const key = await makeKey("k1");
    serveKeys([key.publicKey]);
    const request = await signedRequest(key, BODY, { headers: testHeaders() });

    expect(await new Varis().requests.verify(request)).toBe(false);
  });

  it("only takes the key the CLI serves for this request ID", async () => {
    const key = await makeKey("varis-test");
    cliListening(key, "var_tst_req_someone_else");
    const request = await signedRequest(key, BODY, { headers: testHeaders() });

    expect(await new Varis().requests.verify(request)).toBe(false);
  });

  it("verifies a GET test request with its query", async () => {
    const key = await makeKey("varis-test");
    cliListening(key);
    const request = await signedRequest(key, "", {
      method: "GET",
      url: "http://localhost:3000/v1/weather?city=Port+Harcourt",
      headers: testHeaders(),
    });

    expect(await new Varis().requests.verify(request)).toBe(true);
  });

  it("still verifies gateway requests with their own request ID", async () => {
    const key = await makeKey("k1");
    serveKeys([key.publicKey]);
    const request = await signedRequest(key, BODY, {
      headers: { "x-varis-request-id": "var_req_4f0c2b8e" },
    });

    expect(await new Varis().requests.verify(request)).toBe(true);
  });
});
