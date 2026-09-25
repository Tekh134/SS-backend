import crypto from "crypto";
import jwt, { JwtPayload, type SignOptions } from "jsonwebtoken";
import { DataSource, FindOptionsSelect, IsNull, Repository } from "typeorm";
import { Keypair, StrKey } from "stellar-sdk";
import type { AppConfig } from "../config/env";
import { AuthChallenge } from "../models/AuthChallenge.model";
import { User, USER_PROFILE_SELECT } from "../models/User.model";
import type { PublicUser } from "../types/auth";
import { HttpError } from "../utils/http-error";
import { buildAuthFailureDetails, classifyJwtError } from "../lib/auth-failure";
import type { AppLogger } from "../observability/logger";
import { buildWalletChallenge } from "../utils/stellar-challenge";
import { MetricsRegistry } from "../observability/metrics";

interface ChallengeRecord {
  id: string;
  stellarAddress: string;
  nonceHash: string;
  message: string;
  network: string;
  issuedAt: Date;
  expiresAt: Date;
  consumedAt: Date | null;
}

interface CreateChallengeRecordInput {
  stellarAddress: string;
  nonceHash: string;
  message: string;
  network: string;
  issuedAt: Date;
  expiresAt: Date;
}

export interface UserRepositoryContract {
  findById(id: string): Promise<User | null>;
  findByStellarAddress(stellarAddress: string): Promise<User | null>;
  findByEmail(email: string): Promise<User | null>;
  findAll(options?: {
    skip?: number;
    take?: number;
    cursor?: string;
    order?: "ASC" | "DESC";
  }): Promise<User[]>;
  count(options?: { cursor?: string }): Promise<number>;
  save(user: Partial<User>): Promise<User>;
}

export interface ChallengeRepositoryContract {
  create(input: CreateChallengeRecordInput): Promise<ChallengeRecord>;
  findByAddressAndNonceHash(
    stellarAddress: string,
    nonceHash: string
  ): Promise<ChallengeRecord | null>;
  consume(id: string, consumedAt: Date): Promise<boolean>;
  deleteExpired(before: Date): Promise<number>;
  countByStatus(status: "active" | "consumed" | "expired"): Promise<number>;
}

interface AuthTokenPayload extends JwtPayload {
  sub: string;
  stellarAddress: string;
}

export interface AuthServiceDependencies {
  userRepository: UserRepositoryContract;
  challengeRepository: ChallengeRepositoryContract;
  config: Pick<AppConfig, "jwt" | "auth" | "stellar"> & { serverKeypair?: Keypair };
  logger?: AppLogger;
  metrics?: MetricsRegistry;
}

export interface ChallengeResponse {
  publicKey: string;
  nonce: string;
  message: string;
  issuedAt: string;
  expiresAt: string;
  network: string;
}

export interface VerifyChallengeInput {
  publicKey: string;
  nonce: string;
  signature: string;
  ipAddress?: string;
}

export interface VerifyChallengeResponse {
  token: string;
  tokenType: "Bearer";
  expiresIn: string;
  user: PublicUser;
}

export class AuthService {
  private readonly userRepository: UserRepositoryContract;
  private readonly challengeRepository: ChallengeRepositoryContract;
  private readonly config: Pick<AppConfig, "jwt" | "auth" | "stellar">;
  private readonly logger?: AppLogger;
  private readonly serverKeypair?: Keypair;
  private readonly metrics?: MetricsRegistry;

  constructor(dependencies: AuthServiceDependencies) {
    this.userRepository = dependencies.userRepository;
    this.challengeRepository = dependencies.challengeRepository;
    this.config = dependencies.config;
    this.logger = dependencies.logger;
    this.serverKeypair = dependencies.config.serverKeypair;
    this.metrics = dependencies.metrics;
  }

  private recordChallengeMetric(
    status: "created" | "verified" | "expired" | "failed" | "reused",
    wallet: string
  ): void {
    this.metrics?.increment("auth_challenge_total", { status, wallet: wallet.slice(0, 8) + "..." });
  }

  async createChallenge(publicKey: string): Promise<ChallengeResponse> {
    try {
      const sanitizedKey = publicKey.trim();
      this.assertValidPublicKey(sanitizedKey);

      const issuedAt = new Date();
      const expiresAt = new Date(issuedAt.getTime() + this.config.auth.challengeTtlMs);

      let nonce: string;
      if (this.serverKeypair) {
        ({ nonce } = buildWalletChallenge(
          sanitizedKey,
          this.config.stellar.networkPassphrase,
          this.serverKeypair
        ));
      } else {
        nonce = crypto.randomBytes(32).toString("hex");
      }

      const message = buildChallengeMessage({
        publicKey: sanitizedKey,
        nonce,
        network: this.config.stellar.network,
        networkPassphrase: this.config.stellar.networkPassphrase,
        issuedAt,
        expiresAt,
      });

      try {
        await this.challengeRepository.create({
          stellarAddress: sanitizedKey,
          nonceHash: hashNonce(nonce),
          message,
          network: this.config.stellar.network,
          issuedAt,
          expiresAt,
        });
        this.recordChallengeMetric("created", sanitizedKey);
      } catch (error) {
        this.logger?.error("Failed to persist challenge", { error, stellarAddress: sanitizedKey });
        throw new HttpError(500, "Failed to create challenge.");
      }

      return {
        publicKey: sanitizedKey,
        nonce,
        message,
        issuedAt: issuedAt.toISOString(),
        expiresAt: expiresAt.toISOString(),
        network: this.config.stellar.network,
      };
    } catch (error) {
      if (error instanceof HttpError) throw error;
      this.logger?.error("Unhandled error in createChallenge", {
        error: error instanceof Error ? error.message : String(error),
      });
      throw new HttpError(500, "Failed to create challenge.");
    }
  }

  async verifyChallenge(input: VerifyChallengeInput): Promise<VerifyChallengeResponse> {
    try {
      const sanitizedKey = input.publicKey.trim();
      const sanitizedNonce = input.nonce.trim();
      const sanitizedSig = input.signature.trim();

      this.assertValidPublicKey(sanitizedKey);

      if (!sanitizedNonce || sanitizedNonce.length < 16) {
        throw new HttpError(400, "Invalid nonce.");
      }
      if (!sanitizedSig) {
        throw new HttpError(400, "Signature is required.");
      }

      let challenge: ChallengeRecord | null;
      try {
        challenge = await this.challengeRepository.findByAddressAndNonceHash(
          sanitizedKey,
          hashNonce(sanitizedNonce)
        );
      } catch (error) {
        this.logger?.error("Failed to fetch challenge", { error, stellarAddress: sanitizedKey });
        throw new HttpError(500, "Failed to verify challenge.");
      }

      if (!challenge) {
        throw new HttpError(401, "Invalid challenge.");
      }

      if (challenge.network !== this.config.stellar.network) {
        throw new HttpError(401, "Challenge network mismatch.");
      }

      if (challenge.consumedAt) {
        throw new HttpError(401, "Challenge already used.");
      }

      if (challenge.expiresAt.getTime() <= Date.now()) {
        this.recordChallengeMetric("expired", sanitizedKey);
        throw new HttpError(401, "Challenge expired.");
      }

      const signature = decodeSignature(sanitizedSig);
      const keypair = Keypair.fromPublicKey(sanitizedKey);

      let isValid: boolean;
      try {
        isValid = keypair.verify(Buffer.from(challenge.message, "utf8"), signature);
      } catch (error) {
        this.logger?.warn("auth.signature_verification_failed", {
          wallet: sanitizedKey,
          reason: error instanceof Error ? error.message : "unknown",
        });
        throw new HttpError(401, "Invalid signature.");
      }

      if (!isValid) {
        this.logger?.warn("Invalid challenge signature", { stellarAddress: sanitizedKey });
        this.recordChallengeMetric("failed", sanitizedKey);
        throw new HttpError(401, "Invalid signature.");
      }

      let consumed: boolean;
      try {
        consumed = await this.challengeRepository.consume(challenge.id, new Date());
      } catch (error) {
        this.logger?.error("Failed to consume challenge", { error, challengeId: challenge.id });
        throw new HttpError(500, "Failed to verify challenge.");
      }

      if (!consumed) {
        throw new HttpError(401, "Challenge already used.");
      }

      this.recordChallengeMetric("verified", sanitizedKey);

      let user: User;
      try {
        user = await this.upsertUser(sanitizedKey);
      } catch (error) {
        this.logger?.error("Failed to upsert user", { error, stellarAddress: sanitizedKey });
        throw new HttpError(500, "Failed to verify challenge.");
      }

      const publicUser = toPublicUser(user);
      const token = this.signToken(publicUser);

      const decoded = jwt.decode(token) as { iat?: number; exp?: number } | null;
      this.logger?.info("jwt.issued", {
        wallet: publicUser.stellarAddress,
        issued_at: decoded?.iat
          ? new Date(decoded.iat * 1000).toISOString()
          : new Date().toISOString(),
        expires_at: decoded?.exp ? new Date(decoded.exp * 1000).toISOString() : null,
        ip_address: input.ipAddress ?? null,
      });

      return {
        token,
        tokenType: "Bearer",
        expiresIn: this.config.jwt.expiresIn,
        user: publicUser,
      };
    } catch (error) {
      if (error instanceof HttpError) throw error;
      this.logger?.error("Unhandled error in verifyChallenge", {
        error: error instanceof Error ? error.message : String(error),
      });
      throw new HttpError(500, "Failed to verify challenge.");
    }
  }

  async cleanupExpiredChallenges(maxAgeMs = 24 * 60 * 60 * 1000): Promise<number> {
    const before = new Date(Date.now() - maxAgeMs);
    try {
      const deleted = await this.challengeRepository.deleteExpired(before);
      this.logger?.info("Cleaned up expired challenges", { count: deleted });
      return deleted;
    } catch (error) {
      this.logger?.error("Failed to cleanup expired challenges", { error });
      throw new HttpError(500, "Failed to cleanup expired challenges.");
    }
  }

  async getChallengeMetrics(): Promise<{
    active: number;
    consumed: number;
    expired: number;
  }> {
    try {
      const [active, consumed, expired] = await Promise.all([
        this.challengeRepository.countByStatus("active"),
        this.challengeRepository.countByStatus("consumed"),
        this.challengeRepository.countByStatus("expired"),
      ]);
      return { active, consumed, expired };
    } catch (error) {
      this.logger?.error("Failed to get challenge metrics", { error });
      throw new HttpError(500, "Failed to get challenge metrics.");
    }
  }

  async getCurrentUser(token: string): Promise<PublicUser> {
    let payload: AuthTokenPayload;

    const sanitizedToken = token?.trim();
    if (!sanitizedToken) {
      throw new HttpError(
        401,
        "Invalid or expired token.",
        buildAuthFailureDetails(token, "missing_token")
      );
    }

    try {
      payload = jwt.verify(sanitizedToken, this.config.jwt.secret) as AuthTokenPayload;
    } catch (error) {
      throw new HttpError(
        401,
        "Invalid or expired token.",
        buildAuthFailureDetails(sanitizedToken, classifyJwtError(error))
      );
    }

    if (!payload.sub) {
      throw new HttpError(
        401,
        "Invalid token payload.",
        buildAuthFailureDetails(sanitizedToken, "invalid_token")
      );
    }

    let user: User | null;
    try {
      user = await this.userRepository.findByStellarAddress(payload.sub);
    } catch (error) {
      this.logger?.error("Failed to fetch user by stellar address", { error, sub: payload.sub });
      throw new HttpError(500, "Failed to fetch current user.");
    }

    if (!user) {
      throw new HttpError(401, "User no longer exists.");
    }

    return toPublicUser(user);
  }

  private assertValidPublicKey(publicKey: string): void {
    if (!StrKey.isValidEd25519PublicKey(publicKey)) {
      throw new HttpError(400, "Invalid Stellar public key.");
    }
  }

  private async upsertUser(publicKey: string): Promise<User> {
    const sanitized = publicKey.trim();
    try {
      const existingUser = await this.userRepository.findByStellarAddress(sanitized);

      if (existingUser) {
        return existingUser;
      }

      return await this.userRepository.save({
        stellarAddress: sanitized,
      });
    } catch (error) {
      if (error instanceof Error && error.message.includes("duplicate key")) {
        const existing = await this.userRepository.findByStellarAddress(sanitized);
        if (existing) return existing;
      }
      this.logger?.error("upsertUser failed", { error, publicKey });
      throw error;
    }
  }

  private signToken(user: PublicUser): string {
    const signOptions: SignOptions = {
      expiresIn: this.config.jwt.expiresIn as SignOptions["expiresIn"],
    };

    return jwt.sign(
      {
        stellarAddress: user.stellarAddress,
        userId: user.id,
      },
      this.config.jwt.secret,
      {
        ...signOptions,
        subject: user.stellarAddress,
      }
    );
  }
}

class TypeOrmUserRepository implements UserRepositoryContract {
  constructor(private readonly repository: Repository<User>) {}

  findById(id: string): Promise<User | null> {
    return this.repository.findOne({
      where: { id },
      select: USER_PROFILE_SELECT as unknown as FindOptionsSelect<User>,
    });
  }

  findByStellarAddress(stellarAddress: string): Promise<User | null> {
    return this.repository.findOne({
      where: { stellarAddress },
      select: USER_PROFILE_SELECT as unknown as FindOptionsSelect<User>,
    });
  }

  findByEmail(email: string): Promise<User | null> {
    return this.repository.findOne({
      where: { email },
    });
  }

  findAll(options?: {
    skip?: number;
    take?: number;
    cursor?: string;
    order?: "ASC" | "DESC";
  }): Promise<User[]> {
    const qb = this.repository.createQueryBuilder("user");
    qb.where("user.deletedAt IS NULL");

    if (options?.cursor) {
      const direction = options.order === "ASC" ? ">" : "<";
      qb.andWhere(`user.id ${direction} :cursor`, { cursor: options.cursor });
    }

    qb.orderBy("user.id", options?.order ?? "DESC");
    if (options?.take) qb.take(options.take);
    if (options?.skip) qb.skip(options.skip);

    return qb.getMany();
  }

  async count(options?: { cursor?: string }): Promise<number> {
    const qb = this.repository.createQueryBuilder("user");
    qb.where("user.deletedAt IS NULL");
    if (options?.cursor) {
      qb.andWhere("user.id < :cursor", { cursor: options.cursor });
    }
    return qb.getCount();
  }

  async save(user: Partial<User>): Promise<User> {
    const entity = this.repository.create(user);
    return this.repository.save(entity);
  }
}

class TypeOrmChallengeRepository implements ChallengeRepositoryContract {
  constructor(private readonly repository: Repository<AuthChallenge>) {}

  async create(input: CreateChallengeRecordInput): Promise<ChallengeRecord> {
    const entity = this.repository.create({
      stellarAddress: input.stellarAddress,
      nonceHash: input.nonceHash,
      message: input.message,
      network: input.network,
      issuedAt: input.issuedAt,
      expiresAt: input.expiresAt,
      consumedAt: null,
    });

    return this.repository.save(entity);
  }

  findByAddressAndNonceHash(
    stellarAddress: string,
    nonceHash: string
  ): Promise<ChallengeRecord | null> {
    return this.repository.findOne({
      where: {
        stellarAddress,
        nonceHash,
      },
    });
  }

  async consume(id: string, consumedAt: Date): Promise<boolean> {
    const result = await this.repository.update(
      {
        id,
        consumedAt: IsNull(),
      },
      {
        consumedAt,
      }
    );

    return (result.affected ?? 0) > 0;
  }

  async deleteExpired(before: Date): Promise<number> {
    const result = await this.repository
      .createQueryBuilder()
      .delete()
      .where("expiresAt < :before", { before })
      .orWhere("consumedAt IS NOT NULL AND consumedAt < :before", { before })
      .execute();
    return result.affected ?? 0;
  }

  async countByStatus(status: "active" | "consumed" | "expired"): Promise<number> {
    const qb = this.repository.createQueryBuilder("challenge");
    const now = new Date();
    switch (status) {
      case "active":
        qb.where("challenge.consumedAt IS NULL AND challenge.expiresAt > :now", { now });
        break;
      case "consumed":
        qb.where("challenge.consumedAt IS NOT NULL");
        break;
      case "expired":
        qb.where("challenge.consumedAt IS NULL AND challenge.expiresAt <= :now", { now });
        break;
    }
    return qb.getCount();
  }
}

export function createAuthService(
  dataSource: DataSource,
  config: Pick<AppConfig, "jwt" | "auth" | "stellar">,
  logger?: AppLogger,
  metrics?: MetricsRegistry
): AuthService {
  return new AuthService({
    userRepository: new TypeOrmUserRepository(dataSource.getRepository(User)),
    challengeRepository: new TypeOrmChallengeRepository(dataSource.getRepository(AuthChallenge)),
    config,
    logger,
    metrics,
  });
}

export function buildChallengeMessage(input: {
  publicKey: string;
  nonce: string;
  network: string;
  networkPassphrase: string;
  issuedAt: Date;
  expiresAt: Date;
}): string {
  return [
    "StellarSettle Authentication Challenge",
    `Public Key: ${input.publicKey}`,
    `Network: ${input.network}`,
    `Network Passphrase: ${input.networkPassphrase}`,
    `Nonce: ${input.nonce}`,
    `Issued At: ${input.issuedAt.toISOString()}`,
    `Expires At: ${input.expiresAt.toISOString()}`,
    "",
    "Sign this exact message to authenticate with the StellarSettle API.",
  ].join("\n");
}

function hashNonce(nonce: string): string {
  return crypto.createHash("sha256").update(nonce, "utf8").digest("hex");
}

function decodeSignature(signature: string): Buffer {
  const trimmedSignature = signature.trim();

  if (!trimmedSignature) {
    throw new HttpError(400, "Signature is required.");
  }

  const normalizedHexSignature = trimmedSignature.startsWith("0x")
    ? trimmedSignature.slice(2)
    : trimmedSignature;

  if (/^[a-fA-F0-9]+$/.test(normalizedHexSignature) && normalizedHexSignature.length % 2 === 0) {
    return Buffer.from(normalizedHexSignature, "hex");
  }

  if (!/^[A-Za-z0-9+/_=-]+$/.test(trimmedSignature)) {
    throw new HttpError(400, "Signature must be base64, base64url, or hex encoded.");
  }

  const normalizedBase64Signature = trimmedSignature.replace(/-/g, "+").replace(/_/g, "/");
  const paddingLength = normalizedBase64Signature.length % 4;
  const paddedBase64Signature =
    paddingLength === 0
      ? normalizedBase64Signature
      : `${normalizedBase64Signature}${"=".repeat(4 - paddingLength)}`;

  return Buffer.from(paddedBase64Signature, "base64");
}

export function toPublicUser(user: User): PublicUser {
  return {
    id: user.id,
    stellarAddress: user.stellarAddress,
    email: user.email,
    userType: user.userType,
    kycStatus: user.kycStatus,
    isKycVerified: user.isKycVerified,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
  };
}