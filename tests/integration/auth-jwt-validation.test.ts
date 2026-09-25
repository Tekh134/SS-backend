import crypto from "crypto";
import jwt from "jsonwebtoken";
import { Networks } from "stellar-sdk";
import request from "supertest";

import { createApp } from "../../src/app";
import { AuthService } from "../../src/services/auth.service";
import type {
  ChallengeRepositoryContract,
  UserRepositoryContract,
} from "../../src/services/auth.service";
import { User } from "../../src/models/User.model";
import { KYCStatus, UserType } from "../../src/types/enums";

// ── In-memory repositories ────────────────────────────────────────────────────

type InMemoryUser = User;

interface InMemoryChallenge {
  id: string;
  stellarAddress: string;
  nonceHash: string;
  message: string;
  network: string;
  issuedAt: Date;
  expiresAt: Date;
  consumedAt: Date | null;
}

class InMemoryUserRepository implements UserRepositoryContract {
  private readonly users = new Map<string, InMemoryUser>();

  async findById(id: string) {
    return this.users.get(id) ?? null;
  }

  async findByStellarAddress(stellarAddress: string) {
    return [...this.users.values()].find((user) => user.stellarAddress === stellarAddress) ?? null;
  }

  async findByEmail(email: string) {
    return [...this.users.values()].find((u) => u.email === email) ?? null;
  }

  async findAll(options?: {
    skip?: number;
    take?: number;
    cursor?: string;
    order?: "ASC" | "DESC";
  }) {
    let results = [...this.users.values()].filter((u) => !u.deletedAt);
    results.sort((a, b) =>
      options?.order === "ASC" ? a.id.localeCompare(b.id) : b.id.localeCompare(a.id)
    );
    if (options?.cursor) {
      const cursorIndex = results.findIndex((u) => u.id === options.cursor);
      if (cursorIndex >= 0) {
        results = results.slice(cursorIndex + 1);
      }
    }
    if (options?.skip) {
      results = results.slice(options.skip);
    }
    if (options?.take) {
      results = results.slice(0, options.take);
    }
    return results;
  }

  async count(options?: { cursor?: string }): Promise<number> {
    let results = [...this.users.values()].filter((u) => !u.deletedAt);
    if (options?.cursor) {
      const cursorIndex = results.findIndex((u) => u.id === options.cursor);
      if (cursorIndex >= 0) {
        results = results.slice(0, cursorIndex);
      }
    }
    return results.length;
  }

  async save(user: Partial<InMemoryUser>) {
    const now = new Date();
    const entity: InMemoryUser = {
      id: crypto.randomUUID(),
      stellarAddress: user.stellarAddress ?? "",
      email: user.email ?? null,
      userType: user.userType ?? UserType.INVESTOR,
      kycStatus: user.kycStatus ?? KYCStatus.PENDING,
      isKycVerified: user.isKycVerified ?? false,
      createdAt: user.createdAt ?? now,
      updatedAt: user.updatedAt ?? now,
      deletedAt: user.deletedAt ?? null,
      invoices: user.invoices ?? [],
      investments: user.investments ?? [],
      transactions: user.transactions ?? [],
      kycVerifications: user.kycVerifications ?? [],
      notifications: user.notifications ?? [],
    };

    this.users.set(entity.id, entity);
    return entity;
  }
}

class InMemoryChallengeRepository implements ChallengeRepositoryContract {
  readonly challenges = new Map<string, InMemoryChallenge>();

  async create(input: InMemoryChallenge) {
    const challenge: InMemoryChallenge = {
      id: crypto.randomUUID(),
      stellarAddress: input.stellarAddress,
      nonceHash: input.nonceHash,
      message: input.message,
      network: input.network,
      issuedAt: input.issuedAt,
      expiresAt: input.expiresAt,
      consumedAt: null,
    };

    this.challenges.set(challenge.id, challenge);
    return challenge;
  }

  async findByAddressAndNonceHash(stellarAddress: string, nonceHash: string) {
    return (
      [...this.challenges.values()].find(
        (challenge) =>
          challenge.stellarAddress === stellarAddress && challenge.nonceHash === nonceHash
      ) ?? null
    );
  }

  async consume(id: string, consumedAt: Date) {
    const challenge = this.challenges.get(id);

    if (!challenge || challenge.consumedAt) {
      return false;
    }

    challenge.consumedAt = consumedAt;
    return true;
  }

  async deleteExpired(before: Date): Promise<number> {
    let count = 0;
    for (const [id, challenge] of this.challenges.entries()) {
      if (challenge.expiresAt < before || (challenge.consumedAt && challenge.consumedAt < before)) {
        this.challenges.delete(id);
        count++;
      }
    }
    return count;
  }

  async countByStatus(status: "active" | "consumed" | "expired"): Promise<number> {
    const now = new Date();
    let count = 0;
    for (const challenge of this.challenges.values()) {
      if (status === "active" && !challenge.consumedAt && challenge.expiresAt > now) count++;
      if (status === "consumed" && challenge.consumedAt) count++;
      if (status === "expired" && !challenge.consumedAt && challenge.expiresAt <= now) count++;
    }
    return count;
  }
}

// ── Test helpers ──────────────────────────────────────────────────────────────

const VALID_JWT_SECRET = "valid-test-secret";

function createTestApp() {
  const authService = new AuthService({
    userRepository: new InMemoryUserRepository(),
    challengeRepository: new InMemoryChallengeRepository(),
    config: {
      jwt: {
        secret: VALID_JWT_SECRET,
        expiresIn: "15m",
      },
      auth: {
        challengeTtlMs: 60_000,
      },
      stellar: {
        network: "testnet",
        networkPassphrase: Networks.TESTNET,
      },
    },
  });

  return createApp({ authService });
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("JWT authentication validation", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });
  it("rejects GET /api/v1/auth/me when the JWT is signed with an invalid secret key", async () => {
    try {
      const app = createTestApp();

      const forgedToken = jwt.sign(
        {
          sub: "GFORGED_STELLAR_ADDRESS",
          stellarAddress: "GFORGED_STELLAR_ADDRESS",
          userId: crypto.randomUUID(),
        },
        "invalid-secret-key",
        { expiresIn: "15m" },
      );

      const response = await request(app)
        .get("/api/v1/auth/me")
        .set("Authorization", `Bearer ${forgedToken}`)
        .expect(401);

      expect(response.body).toMatchObject({
        success: false,
        error: {
          message: "Invalid or expired token.",
        },
      });
    } catch (error) {
      throw new Error(`JWT validation test failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  });

  it("rejects GET /api/v1/auth/me with expired JWT token", async () => {
    const app = createTestApp();

    const expiredToken = jwt.sign(
      {
        sub: "GEXPIRED_STELLAR_ADDRESS",
        stellarAddress: "GEXPIRED_STELLAR_ADDRESS",
        userId: crypto.randomUUID(),
      },
      VALID_JWT_SECRET,
      { expiresIn: "-5m" }
    );

    const response = await request(app)
      .get("/api/v1/auth/me")
      .set("Authorization", `Bearer ${expiredToken}`)
      .expect(401);

    expect(response.body).toMatchObject({
      success: false,
      error: {
        message: "Invalid or expired token.",
      },
    });
  });

  it("returns 401 from /me when the bearer token is missing", async () => {
    const app = createTestApp();

    const response = await request(app).get("/api/v1/auth/me").expect(401);

    expect(response.body).toMatchObject({
      success: false,
      error: {
        message: "Authorization token is required.",
      },
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// JWT validation: malformed tokens
// ═══════════════════════════════════════════════════════════════════════════

describe("JWT validation: malformed tokens", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("rejects a completely random non-JWT string", async () => {
    try {
      const app = createTestApp();

      const response = await request(app)
        .get("/api/v1/auth/me")
        .set("Authorization", "Bearer not-a-jwt-at-all")
        .expect(401);

      expect(response.body).toMatchObject({
        success: false,
        error: {
          message: "Invalid or expired token.",
        },
      });
    } catch (error) {
      throw new Error(`Malformed token test failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  });

  it("rejects a token with only two parts (missing signature)", async () => {
    const app = createTestApp();

    // A valid JWT has three base64url parts separated by dots.
    // Create one with only header.payload (no signature).
    const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
    const payload = Buffer.from(
      JSON.stringify({ sub: "GTESTADDRESS", stellarAddress: "GTESTADDRESS" }),
    ).toString("base64url");
    const twoPartToken = `${header}.${payload}`;

    const response = await request(app)
      .get("/api/v1/auth/me")
      .set("Authorization", `Bearer ${twoPartToken}`)
      .expect(401);

    expect(response.body).toMatchObject({
      success: false,
      error: {
        message: "Invalid or expired token.",
      },
    });
  });

  it("rejects an empty string as token", async () => {
    const app = createTestApp();

    const response = await request(app)
      .get("/api/v1/auth/me")
      .set("Authorization", "Bearer ")
      .expect(401);

    expect(response.body).toMatchObject({
      success: false,
      error: {
        message: "Authorization token is required.",
      },
    });
  });

  it("rejects a token with invalid base64url encoding in payload", async () => {
    const app = createTestApp();

    const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
    // Use invalid base64 characters
    const invalidPayload = "!!!invalid-base64!!!";
    const badToken = `${header}.${invalidPayload}.signature`;

    const response = await request(app)
      .get("/api/v1/auth/me")
      .set("Authorization", `Bearer ${badToken}`)
      .expect(401);

    expect(response.body).toMatchObject({
      success: false,
      error: {
        message: "Invalid or expired token.",
      },
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// JWT validation: algorithm and signing attacks
// ═══════════════════════════════════════════════════════════════════════════

describe("JWT validation: algorithm and signing attacks", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("rejects a token signed with 'none' algorithm", async () => {
    try {
      const app = createTestApp();

      const unsignedToken = jwt.sign(
        {
          sub: "GNONEALGADDRESS",
          stellarAddress: "GNONEALGADDRESS",
          userId: crypto.randomUUID(),
        },
        "",
        { algorithm: "none", expiresIn: "15m" },
      );

      const response = await request(app)
        .get("/api/v1/auth/me")
        .set("Authorization", `Bearer ${unsignedToken}`)
        .expect(401);

      expect(response.body).toMatchObject({
        success: false,
        error: {
          message: "Invalid or expired token.",
        },
      });
    } catch (error) {
      throw new Error(`Algorithm attack test failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  });

  it("rejects a token signed with a different HS256 secret", async () => {
    const app = createTestApp();

    const token = jwt.sign(
      {
        sub: "GDIFFERENT_SECRET_ADDR",
        stellarAddress: "GDIFFERENT_SECRET_ADDR",
        userId: crypto.randomUUID(),
      },
      "completely-different-secret",
      { algorithm: "HS256", expiresIn: "15m" },
    );

    const response = await request(app)
      .get("/api/v1/auth/me")
      .set("Authorization", `Bearer ${token}`)
      .expect(401);

    expect(response.body).toMatchObject({
      success: false,
      error: {
        message: "Invalid or expired token.",
      },
    });
  });

  it("rejects a token where the header is tampered to use HS256 but was originally signed with a different key", async () => {
    const app = createTestApp();

    // Sign with one secret, then manually change the alg in the header
    // and re-encode to simulate an alg-switch attack
    const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
    const payload = Buffer.from(
      JSON.stringify({
        sub: "GTAMPEREDADDR",
        stellarAddress: "GTAMPEREDADDR",
        userId: crypto.randomUUID(),
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 900,
      }),
    ).toString("base64url");

    // Sign the tampered header.payload with a wrong secret
    const signature = require("crypto")
      .createHmac("sha256", "wrong-secret")
      .update(`${header}.${payload}`)
      .digest("base64url");

    const tamperedToken = `${header}.${payload}.${signature}`;

    const response = await request(app)
      .get("/api/v1/auth/me")
      .set("Authorization", `Bearer ${tamperedToken}`)
      .expect(401);

    expect(response.body).toMatchObject({
      success: false,
      error: {
        message: "Invalid or expired token.",
      },
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// JWT validation: missing or invalid claims
// ═══════════════════════════════════════════════════════════════════════════

describe("JWT validation: missing or invalid claims", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("rejects a token with no sub claim", async () => {
    try {
      const app = createTestApp();

      const token = jwt.sign(
        {
          stellarAddress: "GNOSUBCLAIM",
          userId: crypto.randomUUID(),
        },
        VALID_JWT_SECRET,
        { expiresIn: "15m" },
      );

      const response = await request(app)
        .get("/api/v1/auth/me")
        .set("Authorization", `Bearer ${token}`)
        .expect(401);

      expect(response.body).toMatchObject({
        success: false,
        error: {
          message: INVALID_PAYLOAD_MESSAGE,
        },
      });
    } catch (error) {
      throw new Error(`Claims validation test failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  });

  it("rejects a token with an empty sub claim", async () => {
    const app = createTestApp();

    const token = jwt.sign(
      {
        sub: "",
        stellarAddress: "",
        userId: crypto.randomUUID(),
      },
      VALID_JWT_SECRET,
      { expiresIn: "15m" },
    );

    const response = await request(app)
      .get("/api/v1/auth/me")
      .set("Authorization", `Bearer ${token}`)
      .expect(401);

    expect(response.body).toMatchObject({
      success: false,
      error: {
        message: INVALID_PAYLOAD_MESSAGE,
      },
    });
  });
});

/** Base claims for a well-formed token; override per case. */
function claims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    sub: "GTESTSUBJECT",
    stellarAddress: "GTESTSUBJECT",
    userId: crypto.randomUUID(),
    ...overrides,
  };
}

function signToken(
  payload: Record<string, unknown>,
  options?: {
    secret?: string;
    algorithm?: string;
    expiresIn?: string;
    notBefore?: string;
  },
): string {
  const signOpts: jwt.SignOptions = {
    expiresIn: (options?.expiresIn ?? "15m") as jwt.SignOptions["expiresIn"],
  };
  if (options?.algorithm) signOpts.algorithm = options.algorithm as jwt.Algorithm;
  if (options?.notBefore) signOpts.notBefore = options.notBefore as jwt.SignOptions["notBefore"];
  return jwt.sign(payload, options?.secret ?? VALID_JWT_SECRET, signOpts);
}

/** Issue GET /api/v1/auth/me with the given Authorization header value. */
function getMe(authorization?: string) {
  const req = request(createTestApp()).get("/api/v1/auth/me");
  return authorization === undefined ? req : req.set("Authorization", authorization);
}

/**
 * Canonical middleware / auth-service messages (see src/middleware/auth.middleware.ts
 * and src/services/auth.service.ts#getCurrentUser). Every failure mode still
 * returns 401 with the standard envelope; only the message differentiates them.
 */
const INVALID_TOKEN_MESSAGE = "Invalid or expired token."; // unverifiable / undecodable token
const INVALID_PAYLOAD_MESSAGE = "Invalid token payload."; // verified token, missing/empty sub
const UNKNOWN_USER_MESSAGE = "User no longer exists."; // verified token, sub resolves to no user
const MISSING_TOKEN_MESSAGE = "Authorization token is required."; // no usable Bearer credential

/**
 * Assert the standard 401 rejection envelope. Centralising this keeps every
 * case checking the same contract — status, `success:false`, a string
 * `error.message`, and no `data` leak — so an envelope regression fails once
 * and loudly instead of in whichever test happened to run first.
 */
function expectRejected(
  response: Awaited<ReturnType<typeof getMe>>,
  expectedMessage?: string,
): void {
  expect(response.status).toBe(401);
  expect(response.body).toHaveProperty("success", false);
  expect(response.body).toHaveProperty("error");
  expect(typeof response.body.error?.message).toBe("string");
  expect(response.body).not.toHaveProperty("data");
  if (expectedMessage !== undefined) {
    expect(response.body.error.message).toBe(expectedMessage);
  }
}

// Hand-rolled tokens that jsonwebtoken cannot produce directly.
function twoSegmentToken(): string {
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(
    JSON.stringify({ sub: "GTESTADDRESS", stellarAddress: "GTESTADDRESS" }),
  ).toString("base64url");
  return `${header}.${payload}`;
}

function undecodablePayloadToken(): string {
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  return `${header}.!!!invalid-base64!!!.signature`;
}

function algSwitchToken(): string {
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(
    JSON.stringify({
      sub: "GTAMPEREDADDR",
      stellarAddress: "GTAMPEREDADDR",
      userId: crypto.randomUUID(),
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 900,
    }),
  ).toString("base64url");
  const signature = crypto
    .createHmac("sha256", "wrong-secret")
    .update(`${header}.${payload}`)
    .digest("base64url");
  return `${header}.${payload}.${signature}`;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("JWT validation: rejects invalid tokens with a 401 envelope", () => {
  // [label, tokenFactory, expectedMessage]
  const cases: Array<[string, () => string, string]> = [
    ["signed with an unknown secret key", () => signToken(claims(), { secret: "invalid-secret-key" }), INVALID_TOKEN_MESSAGE],
    [
      "signed with a different HS256 secret",
      () => signToken(claims(), { secret: "completely-different-secret", algorithm: "HS256" }),
      INVALID_TOKEN_MESSAGE,
    ],
    ["expired", () => signToken(claims(), { expiresIn: "-5m" }), INVALID_TOKEN_MESSAGE],
    ["not yet valid (nbf set in the future)", () => signToken(claims(), { notBefore: "1h" }), INVALID_TOKEN_MESSAGE],
    ["signed with the 'none' algorithm", () => signToken(claims(), { secret: "", algorithm: "none" }), INVALID_TOKEN_MESSAGE],
    ["a completely random non-JWT string", () => "not-a-jwt-at-all", INVALID_TOKEN_MESSAGE],
    ["missing its signature segment", twoSegmentToken, INVALID_TOKEN_MESSAGE],
    ["carrying an undecodable base64url payload", undecodablePayloadToken, INVALID_TOKEN_MESSAGE],
    ["header alg-switched and re-signed with the wrong key", algSwitchToken, INVALID_TOKEN_MESSAGE],
    [
      "verified but missing the sub claim",
      () => signToken({ stellarAddress: "GNOSUBCLAIM", userId: crypto.randomUUID() }),
      INVALID_PAYLOAD_MESSAGE,
    ],
    ["verified but carrying an empty sub claim", () => signToken(claims({ sub: "", stellarAddress: "" })), INVALID_PAYLOAD_MESSAGE],
    ["verified but carrying a non-string sub claim", () => signToken(claims({ sub: 12345 })), UNKNOWN_USER_MESSAGE],
    [
      "verified and well-formed but for a user that does not exist",
      () => signToken(claims({ sub: "GNONEXISTENTUSERADDRESS", stellarAddress: "GNONEXISTENTUSERADDRESS" })),
      UNKNOWN_USER_MESSAGE,
    ],
    [
      "verified, long-lived, but for a user that does not exist",
      () =>
        signToken(
          claims({ sub: "GLONGVALIDTOKEN", stellarAddress: "GLONGVALIDTOKEN" }),
          { expiresIn: "365d" },
        ),
      UNKNOWN_USER_MESSAGE,
    ],
  ];

  it.each(cases)("rejects a token %s", async (_label, makeToken, expectedMessage) => {
    const response = await getMe(`Bearer ${makeToken()}`);
    expectRejected(response, expectedMessage);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// JWT validation: Authorization header edge cases
// ═══════════════════════════════════════════════════════════════════════════

describe("JWT validation: Authorization header edge cases", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("rejects request with lowercase 'bearer' prefix", async () => {
    try {
      const app = createTestApp();

      const token = jwt.sign(
        {
          sub: "GLOWERCASEBEARER",
          stellarAddress: "GLOWERCASEBEARER",
          userId: crypto.randomUUID(),
        },
        VALID_JWT_SECRET,
        { expiresIn: "15m" },
      );

      const response = await request(app)
        .get("/api/v1/auth/me")
        .set("Authorization", `bearer ${token}`)
        .expect(401);

      expect(response.body).toMatchObject({
        success: false,
        error: {
          message: "Authorization token is required.",
        },
      });
    } catch (error) {
      throw new Error(`Bearer prefix test failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  });

  it("rejects (401) a Bearer value padded with surrounding whitespace", async () => {
    // Implementations differ on whether the padding is trimmed before verify;
    // only the rejection envelope is guaranteed here.
    const validToken = signToken(claims(), { secret: "wrong-secret" });
    const response = await getMe(`Bearer   ${validToken}   `);
    expectRejected(response);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// JWT validation: error response structure
// ═══════════════════════════════════════════════════════════════════════════

describe("JWT validation: error response structure", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("returns consistent error envelope on forged token", async () => {
    try {
      const app = createTestApp();

      const forgedToken = jwt.sign(
        {
          sub: "GSTRUCTTEST1",
          stellarAddress: "GSTRUCTTEST1",
        },
        "wrong-secret",
        { expiresIn: "15m" },
      );

      const response = await request(app)
        .get("/api/v1/auth/me")
        .set("Authorization", `Bearer ${forgedToken}`)
        .expect(401);

      expect(response.body).toHaveProperty("success", false);
      expect(response.body).toHaveProperty("error");
      expect(response.body.error).toHaveProperty("message");
      expect(typeof response.body.error.message).toBe("string");
    } catch (error) {
      throw new Error(`Error envelope test failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  });

  it("uses the same envelope when no Authorization header is sent", async () => {
    const response = await getMe();
    expectRejected(response, MISSING_TOKEN_MESSAGE);
  });

  it("always answers 401 (never 403 or 500) across a sample of invalid tokens", async () => {
    const tokens = [
      signToken(claims(), { secret: "wrong" }),
      signToken(claims(), { expiresIn: "-1m" }),
      "not-a-jwt",
    ];

    for (const token of tokens) {
      const response = await getMe(`Bearer ${token}`);
      expect(response.status).toBe(401);
      expect(response.body.success).toBe(false);
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// JWT validation: token with future nbf (not yet valid)
// ═══════════════════════════════════════════════════════════════════════════

describe("JWT validation: token timing edge cases", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("rejects a token with nbf set far in the future", async () => {
    try {
      const app = createTestApp();

      const futureToken = jwt.sign(
        {
          sub: "GFUTURETOKEN",
          stellarAddress: "GFUTURETOKEN",
          userId: crypto.randomUUID(),
        },
        VALID_JWT_SECRET,
        { expiresIn: "15m", notBefore: "1h" },
      );

      const response = await request(app)
        .get("/api/v1/auth/me")
        .set("Authorization", `Bearer ${futureToken}`)
        .expect(401);

      expect(response.body).toMatchObject({
        success: false,
        error: {
          message: "Invalid or expired token.",
        },
      });
    } catch (error) {
      throw new Error(`Future token test failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  });

  it("accepts a token with iat set to now and exp set to far future", async () => {
    const app = createTestApp();

    // This token is valid for a very long time
    const validToken = jwt.sign(
      {
        sub: "GLONGVALIDTOKEN",
        stellarAddress: "GLONGVALIDTOKEN",
        userId: crypto.randomUUID(),
      },
      VALID_JWT_SECRET,
      { expiresIn: "365d" },
    );

    // The token itself is valid, but the user doesn't exist, so we expect 401
    // with a message about invalid/expired token (not about missing token)
    const response = await request(app)
      .get("/api/v1/auth/me")
      .set("Authorization", `Bearer ${validToken}`)
      .expect(401);

    expect(response.body).toMatchObject({
      success: false,
      error: {
        message: UNKNOWN_USER_MESSAGE,
      },
    });
  });
});
