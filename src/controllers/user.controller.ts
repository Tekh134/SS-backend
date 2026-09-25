import type { NextFunction, Response } from "express";
import type { AuthenticatedRequest } from "../types/auth";
import { HttpError, AppError } from "../utils/http-error";
import { logger as defaultLogger, type AppLogger } from "../observability/logger";
import { isValidStellarPublicKey } from "../utils/stellar-address.utils";
import { UserType } from "../types/enums";

export interface UserRepositoryContract {
  findById(id: string): Promise<import("../models/User.model").User | null>;
  findByStellarAddress(address: string): Promise<import("../models/User.model").User | null>;
  findByEmail(email: string): Promise<import("../models/User.model").User | null>;
  findAll(options?: {
    skip?: number;
    take?: number;
    cursor?: string;
    order?: "ASC" | "DESC";
  }): Promise<import("../models/User.model").User[]>;
  count(options?: { cursor?: string }): Promise<number>;
  save(
    user: Partial<import("../models/User.model").User>
  ): Promise<import("../models/User.model").User>;
}

export interface UserControllerDeps {
  userRepository: UserRepositoryContract;
  logger?: AppLogger;
}

const MAX_CURSOR_LIMIT = 100;
const DEFAULT_CURSOR_LIMIT = 20;

function sanitizeString(value: unknown, maxLength = 255): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  return trimmed.slice(0, maxLength);
}

function sanitizeCursor(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  if (!/^[0-9a-fA-F-]{36}$/.test(trimmed)) return null;
  return trimmed;
}

function toPublicUser(user: import("../models/User.model").User) {
  return {
    id: user.id,
    stellarAddress: user.stellarAddress,
    email: user.email,
    userType: user.userType,
    kycStatus: user.kycStatus,
    isKycVerified: user.isKycVerified ?? false,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
  };
}

function getRequestId(req: AuthenticatedRequest): string {
  return (
    (req.headers["x-request-id"] as string) ||
    ((req as unknown as Record<string, unknown>).requestId as string) ||
    "unknown"
  );
}

function setCacheHeaders(res: Response, user: import("../models/User.model").User): void {
  const etag = `W/"${user.id}-${user.updatedAt.getTime()}"`;
  res.setHeader("ETag", etag);
  res.setHeader("Last-Modified", user.updatedAt.toUTCString());
  res.setHeader("Cache-Control", "private, max-age=60");
}

export function createUserController(deps: UserControllerDeps) {
  const userRepository = deps.userRepository;
  const appLogger = deps.logger ?? defaultLogger;

  return {
    async getProfile(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
      const requestId = getRequestId(req);
      try {
        if (!req.user?.id) {
          throw new HttpError(401, "Authentication required");
        }
        const user = await userRepository.findById(req.user.id);
        if (!user) {
          throw new HttpError(404, "User not found");
        }
        setCacheHeaders(res, user);
        res.status(200).json({ success: true, data: toPublicUser(user), requestId });
      } catch (error) {
        if (error instanceof HttpError || error instanceof AppError) {
          next(error);
          return;
        }
        appLogger.error("Failed to fetch user profile", {
          error: error instanceof Error ? error.message : String(error),
          userId: req.user?.id,
          requestId,
        });
        next(new AppError(500, "Failed to fetch profile", "PROFILE_FETCH_FAILED"));
      }
    },

    async getUserById(
      req: AuthenticatedRequest & { params: { id: string } },
      res: Response,
      next: NextFunction
    ): Promise<void> {
      const requestId = getRequestId(req);
      try {
        if (!req.user) {
          throw new HttpError(401, "Authentication required");
        }
        const rawId = sanitizeString(req.params.id, 64);
        if (!rawId) {
          throw new HttpError(400, "Invalid user id");
        }
        // Consistent 404 response if user does not exist
        const user = await userRepository.findById(rawId);
        if (!user) {
          throw new HttpError(404, "User not found");
        }
        setCacheHeaders(res, user);
        res.status(200).json({ success: true, data: toPublicUser(user), requestId });
      } catch (error) {
        if (error instanceof HttpError || error instanceof AppError) {
          next(error);
          return;
        }
        appLogger.error("Failed to fetch user by id", {
          error: error instanceof Error ? error.message : String(error),
          params: req.params,
          requestId,
        });
        next(new AppError(500, "Failed to fetch user", "USER_FETCH_FAILED"));
      }
    },

    async updateProfile(
      req: AuthenticatedRequest,
      res: Response,
      next: NextFunction
    ): Promise<void> {
      const requestId = getRequestId(req);
      try {
        if (!req.user?.id) {
          throw new HttpError(401, "Authentication required");
        }

        const email = sanitizeString(req.body?.email, 255);
        const stellarAddressRaw = sanitizeString(req.body?.stellarAddress, 56);
        const userTypeRaw = req.body?.userType;

        if (email !== null) {
          const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
          if (!emailRegex.test(email)) {
            throw new HttpError(400, "Invalid email format");
          }
          const existingEmail = await userRepository.findByEmail(email);
          if (existingEmail && existingEmail.id !== req.user.id) {
            throw new HttpError(409, "Email already in use");
          }
        }

        if (stellarAddressRaw !== null && !isValidStellarPublicKey(stellarAddressRaw)) {
          throw new HttpError(400, "Invalid Stellar public key");
        }

        if (
          userTypeRaw !== undefined &&
          userTypeRaw !== null &&
          !Object.values(UserType).includes(userTypeRaw)
        ) {
          throw new HttpError(400, "Invalid user type");
        }

        if (email === null && stellarAddressRaw === null && (userTypeRaw === undefined || userTypeRaw === null)) {
          throw new HttpError(400, "No valid fields to update");
        }

        const existing = await userRepository.findById(req.user.id);
        if (!existing) {
          throw new HttpError(404, "User not found");
        }

        const patch: Partial<import("../models/User.model").User> = {};
        if (email !== null) patch.email = email.toLowerCase();
        if (stellarAddressRaw !== null) patch.stellarAddress = stellarAddressRaw;
        if (userTypeRaw) patch.userType = userTypeRaw;

        const updated = await userRepository.save({ ...existing, ...patch });

        appLogger.info("User profile updated", {
          userId: req.user.id,
          updatedFields: Object.keys(patch),
          requestId,
        });

        setCacheHeaders(res, updated);
        res.status(200).json({ success: true, data: toPublicUser(updated), requestId });
      } catch (error) {
        if (error instanceof HttpError || error instanceof AppError) {
          next(error);
          return;
        }
        appLogger.error("Failed to update user profile", {
          error: error instanceof Error ? error.message : String(error),
          userId: req.user?.id,
          requestId,
        });
        next(new AppError(500, "Failed to update profile", "PROFILE_UPDATE_FAILED"));
      }
    },

    async listUsers(
      req: AuthenticatedRequest & {
        query: { page?: string; limit?: string; cursor?: string; order?: string };
      },
      res: Response,
      next: NextFunction
    ): Promise<void> {
      const requestId = getRequestId(req);
      try {
        if (!req.user) {
          throw new HttpError(401, "Authentication required");
        }

        const useCursor = typeof req.query.cursor === "string" && req.query.cursor.length > 0;
        let cursor: string | null = null;
        let limit = DEFAULT_CURSOR_LIMIT;
        let order: "ASC" | "DESC" = "DESC";

        if (useCursor) {
          cursor = sanitizeCursor(req.query.cursor);
          if (!cursor) {
            throw new HttpError(400, "Invalid cursor format");
          }
          limit = Math.min(
            Math.max(Number(req.query.limit) || DEFAULT_CURSOR_LIMIT, 1),
            MAX_CURSOR_LIMIT
          );
          if (req.query.order === "asc" || req.query.order === "ASC") {
            order = "ASC";
          }
        } else {
          const _page = Math.min(Math.max(Number(req.query.page) || 1, 1), 1000);
          limit = Math.min(Math.max(Number(req.query.limit) || 20, 1), 100);
        }

        let users: import("../models/User.model").User[] = [];
        let total = 0;
        let nextCursor: string | undefined = undefined;

        try {
          if (useCursor) {
            users = await userRepository.findAll({
              cursor: cursor ?? undefined,
              take: limit + 1,
              order,
            });
            total = await userRepository.count({ cursor: cursor ?? undefined });
            if (users.length > limit) {
              const nextUser = users.pop();
              nextCursor = nextUser!.id;
            }
          } else {
            const page = Math.min(Math.max(Number(req.query.page) || 1, 1), 1000);
            const skip = (page - 1) * limit;
            const [fetchedUsers, fetchedTotal] = await Promise.all([
              userRepository.findAll({ skip, take: limit }),
              userRepository.count ? userRepository.count() : Promise.resolve(0),
            ]);
            users = fetchedUsers;
            total = fetchedTotal;
          }
        } catch (error) {
          appLogger.error("Failed to list users", { error, requestId });
          throw new AppError(500, "Failed to list users", "USER_LIST_FAILED");
        }

        const response: {
          success: boolean;
          data: ReturnType<typeof toPublicUser>[];
          requestId: string;
          meta?: Record<string, unknown>;
        } = {
          success: true,
          data: users.map(toPublicUser),
          requestId,
        };

        if (useCursor) {
          response.meta = { total, limit, nextCursor };
        } else {
          const page = Math.min(Math.max(Number(req.query.page) || 1, 1), 1000);
          response.meta = { total, page, limit, totalPages: Math.ceil(total / limit) };
        }

        res.status(200).json(response);
      } catch (error) {
        if (error instanceof HttpError || error instanceof AppError) {
          next(error);
          return;
        }
        appLogger.error("Unhandled error in listUsers", {
          error: error instanceof Error ? error.message : String(error),
          requestId,
        });
        next(new AppError(500, "Processing failed", "USER_LIST_FAILED"));
      }
    },
  };
}
