import request from "supertest";
import express from "express";
import jwt from "jsonwebtoken";
import {
  createWalletRateLimiter,
  resetRateLimitStores,
} from "../src/middleware/rate-limit-wallet.middleware";
import { createErrorMiddleware } from "../src/middleware/error.middleware";
import { logger } from "../src/observability/logger";
import { KYCStatus, UserType } from "../src/types/enums";

describe("Wallet-based rate limiting", () => {
  const TEST_SECRET = "test-secret-rate-limit";
  const WALLET_A = "GAWalletA123456789012345678901234567890123456789012345";
  const WALLET_B = "GBWalletB123456789012345678901234567890123456789012345";

  function createToken(walletAddress: string): string {
    return jwt.sign({ sub: walletAddress, stellarAddress: walletAddress }, TEST_SECRET);
  }

  let app: express.Application;

  beforeEach(() => {
    resetRateLimitStores();

    process.env.JWT_SECRET = TEST_SECRET;

    app = express();
    app.use(express.json());

    // Create a test endpoint with wallet rate limiter (max 3 per 60s)
    const testRateLimiter = createWalletRateLimiter(
      { windowMs: 60_000, maxRequests: 3 },
      "test-endpoint"
    );

    app.post(
      "/api/v1/test-rate-limit",
      (req, res, next) => {
        const authHeader = req.headers.authorization;
        if (!authHeader?.startsWith("Bearer ")) {
          res.status(401).json({ error: "Unauthorized" });
          return;
        }
        const token = authHeader.slice(7);
        try {
          const payload = jwt.verify(token, TEST_SECRET) as any;
          (req as any).user = {
            id: payload.sub,
            stellarAddress: payload.stellarAddress,
            email: null,
            userType: UserType.INVESTOR,
            kycStatus: KYCStatus.APPROVED,
            createdAt: new Date(),
            updatedAt: new Date(),
          };
          next();
        } catch {
          res.status(401).json({ error: "Invalid token" });
        }
      },
      testRateLimiter,
      (_req, res) => {
        res.status(200).json({ success: true });
      }
    );

    app.use(createErrorMiddleware(logger));
  });

  afterEach(() => {
    delete process.env.JWT_SECRET;
  });

  it("should allow requests up to the limit", async () => {
    const tokenA = createToken(WALLET_A);

    // First 3 requests should succeed
    for (let i = 0; i < 3; i++) {
      await request(app)
        .post("/api/v1/test-rate-limit")
        .set("Authorization", `Bearer ${tokenA}`)
        .expect(200);
    }
  });

  it("should return 429 after exceeding the limit", async () => {
    const tokenA = createToken(WALLET_A);

    // Exhaust the 3 request limit
    for (let i = 0; i < 3; i++) {
      await request(app)
        .post("/api/v1/test-rate-limit")
        .set("Authorization", `Bearer ${tokenA}`)
        .expect(200);
    }

    // 4th request should be rate limited
    const response = await request(app)
      .post("/api/v1/test-rate-limit")
      .set("Authorization", `Bearer ${tokenA}`)
      .expect(429);

    expect(response.body).toMatchObject({
      success: false,
      error: {
        code: "RATE_LIMIT_EXCEEDED",
      },
    });
  });

  it("should include Retry-After header in 429 response", async () => {
    const tokenA = createToken(WALLET_A);

    // Exhaust the limit
    for (let i = 0; i < 3; i++) {
      await request(app)
        .post("/api/v1/test-rate-limit")
        .set("Authorization", `Bearer ${tokenA}`)
        .expect(200);
    }

    const response = await request(app)
      .post("/api/v1/test-rate-limit")
      .set("Authorization", `Bearer ${tokenA}`)
      .expect(429);

    expect(response.headers).toHaveProperty("retry-after");
    const retryAfter = parseInt(response.headers["retry-after"], 10);
    expect(retryAfter).toBeGreaterThanOrEqual(1);
    expect(retryAfter).toBeLessThanOrEqual(60);
  });

  it("should not affect wallet B when wallet A is rate limited", async () => {
    const tokenA = createToken(WALLET_A);
    const tokenB = createToken(WALLET_B);

    // Exhaust wallet A's limit
    for (let i = 0; i < 3; i++) {
      await request(app)
        .post("/api/v1/test-rate-limit")
        .set("Authorization", `Bearer ${tokenA}`)
        .expect(200);
    }

    // Wallet A should be rate limited
    await request(app)
      .post("/api/v1/test-rate-limit")
      .set("Authorization", `Bearer ${tokenA}`)
      .expect(429);

    // Wallet B should still be allowed
    await request(app)
      .post("/api/v1/test-rate-limit")
      .set("Authorization", `Bearer ${tokenB}`)
      .expect(200);
  });

  it("should allow requests again after the window resets", async () => {
    // Use a very short window for testing
    resetRateLimitStores();

    const shortWindowApp = express();
    shortWindowApp.use(express.json());

    const shortWindowLimiter = createWalletRateLimiter(
      { windowMs: 100, maxRequests: 1 }, // 100ms window, 1 request max
      "short-window-test"
    );

    shortWindowApp.post(
      "/api/v1/short-window",
      (req, res, next) => {
        const authHeader = req.headers.authorization;
        if (!authHeader?.startsWith("Bearer ")) {
          res.status(401).json({ error: "Unauthorized" });
          return;
        }
        const token = authHeader.slice(7);
        try {
          const payload = jwt.verify(token, TEST_SECRET) as any;
          (req as any).user = {
            id: payload.sub,
            stellarAddress: payload.stellarAddress,
            email: null,
            userType: UserType.INVESTOR,
            kycStatus: KYCStatus.APPROVED,
            createdAt: new Date(),
            updatedAt: new Date(),
          };
          next();
        } catch {
          res.status(401).json({ error: "Invalid token" });
        }
      },
      shortWindowLimiter,
      (_req, res) => {
        res.status(200).json({ success: true });
      }
    );

    shortWindowApp.use(createErrorMiddleware(logger));

    const tokenA = createToken(WALLET_A);

    // First request should succeed
    await request(shortWindowApp)
      .post("/api/v1/short-window")
      .set("Authorization", `Bearer ${tokenA}`)
      .expect(200);

    // Second request should be rate limited
    await request(shortWindowApp)
      .post("/api/v1/short-window")
      .set("Authorization", `Bearer ${tokenA}`)
      .expect(429);

    // Wait for window to reset
    await new Promise((resolve) => setTimeout(resolve, 150));

    // After window reset, requests should succeed again
    await request(shortWindowApp)
      .post("/api/v1/short-window")
      .set("Authorization", `Bearer ${tokenA}`)
      .expect(200);
  });

  it("should return 401 if no wallet address in request", async () => {
    // Send request without auth
    await request(app).post("/api/v1/test-rate-limit").expect(401);
  });

  it("should reset counter after window expires and allow full quota again", async () => {
    resetRateLimitStores();

    const shortApp = express();
    shortApp.use(express.json());

    const limiter = createWalletRateLimiter({ windowMs: 150, maxRequests: 3 }, "reset-test");

    shortApp.post(
      "/test",
      (req, res, next) => {
        const authHeader = req.headers.authorization;
        if (!authHeader?.startsWith("Bearer ")) {
          res.status(401).json({ error: "Unauthorized" });
          return;
        }
        const token = authHeader.slice(7);
        try {
          const payload = jwt.verify(token, TEST_SECRET) as any;
          (req as any).user = { id: payload.sub, stellarAddress: payload.stellarAddress };
          next();
        } catch {
          res.status(401).json({ error: "Invalid token" });
        }
      },
      limiter,
      (_req, res) => {
        res.status(200).json({ success: true });
      }
    );

    shortApp.use(createErrorMiddleware(logger));

    const token = createToken(WALLET_A);

    // Exhaust the limit (3 requests)
    for (let i = 0; i < 3; i++) {
      await request(shortApp).post("/test").set("Authorization", `Bearer ${token}`).expect(200);
    }

    // 4th request should be rate limited
    await request(shortApp).post("/test").set("Authorization", `Bearer ${token}`).expect(429);
    // Wait for window to expire
    await new Promise((resolve) => setTimeout(resolve, 200));

    // Counter should have reset — 3 more requests should succeed
    for (let i = 0; i < 3; i++) {
      await request(shortApp).post("/test").set("Authorization", `Bearer ${token}`).expect(200);
    }

    // 4th request after reset should be rate limited again
    await request(shortApp).post("/test").set("Authorization", `Bearer ${token}`).expect(429);
  });

  it("should reset per wallet, not globally", async () => {
    resetRateLimitStores();

    const shortApp = express();
    shortApp.use(express.json());

    const limiter = createWalletRateLimiter({ windowMs: 200, maxRequests: 2 }, "per-wallet-test");

    shortApp.post(
      "/test",
      (req, res, next) => {
        const authHeader = req.headers.authorization;
        if (!authHeader?.startsWith("Bearer ")) {
          res.status(401).json({ error: "Unauthorized" });
          return;
        }
        const token = authHeader.slice(7);
        try {
          const payload = jwt.verify(token, TEST_SECRET) as any;
          (req as any).user = { id: payload.sub, stellarAddress: payload.stellarAddress };
          next();
        } catch {
          res.status(401).json({ error: "Invalid token" });
        }
      },
      limiter,
      (_req, res) => {
        res.status(200).json({ success: true });
      }
    );

    shortApp.use(createErrorMiddleware(logger));

    const tokenA = createToken(WALLET_A);
    const tokenB = createToken(WALLET_B);

    // Exhaust wallet A (max 2)
    await request(shortApp).post("/test").set("Authorization", `Bearer ${tokenA}`).expect(200);
    await request(shortApp).post("/test").set("Authorization", `Bearer ${tokenA}`).expect(200);
    await request(shortApp).post("/test").set("Authorization", `Bearer ${tokenA}`).expect(429);

    // Wallet B should still have full quota
    await request(shortApp).post("/test").set("Authorization", `Bearer ${tokenB}`).expect(200);
    await request(shortApp).post("/test").set("Authorization", `Bearer ${tokenB}`).expect(200);
    await request(shortApp).post("/test").set("Authorization", `Bearer ${tokenB}`).expect(429);

    // Wait for window to expire
    await new Promise((resolve) => setTimeout(resolve, 300));

    // Both wallets should have fresh quotas
    await request(shortApp).post("/test").set("Authorization", `Bearer ${tokenA}`).expect(200);
    await request(shortApp).post("/test").set("Authorization", `Bearer ${tokenB}`).expect(200);
  });
});
