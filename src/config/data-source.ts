/**
 * DataSource entry point consumed by the TypeORM CLI
 * (`migration:run`, `migration:revert`, `migration:generate`, `migration:show`).
 *
 * This module is intentionally a thin re-export of the application DataSource
 * defined in `./database`, so the CLI and the running application always share
 * exactly one connection configuration.
 *
 * On top of that, this module performs a fast-failing pre-flight check with
 * actionable logging: a misconfigured environment otherwise surfaces as an
 * opaque driver error deep inside a migration transaction, which is painful to
 * diagnose in CI/CD.
 *
 * The runtime helpers below (`initializeDataSource`, `closeDataSource`,
 * `getDataSource`) are idempotent and thread-safe so they can be reused from
 * both the long-running HTTP server (`src/index.ts`) and CLI processes without
 * risking double-initialization or torn-down connections.
 */
import { DataSource } from "typeorm";
import { logger } from "../observability/logger";
import { AppError } from "../utils/http-error";
import dataSource from "./database";

function assertValidDataSource(source: unknown): asserts source is DataSource {
  if (!source || typeof source !== "object") {
    throw new AppError(
      500,
      "DataSource is not properly initialized. Check database configuration.",
      "DATASOURCE_INVALID",
      { received: typeof source },
    );
  }

  const candidate = source as Partial<DataSource>;
  if (typeof candidate.initialize !== "function" || typeof candidate.isInitialized !== "boolean") {
    throw new AppError(
      500,
      "DataSource is missing required TypeORM methods.",
      "DATASOURCE_SHAPE_INVALID",
    );
  }
}

assertValidDataSource(dataSource);

let initializationPromise: Promise<DataSource> | null = null;

function describeDataSource(source: DataSource): Record<string, unknown> {
  const driverType = (source.options as { type?: string } | undefined)?.type ?? "unknown";
  const isProduction = process.env.NODE_ENV === "production";
  return {
    driver: driverType,
    environment: process.env.NODE_ENV ?? "development",
    production: isProduction,
    auto_migrations: (source.options as { migrationsRun?: boolean } | undefined)?.migrationsRun === true,
  };
}

async function initializeInternal(source: DataSource): Promise<DataSource> {
  try {
    if (source.isInitialized) {
      logger.debug("DataSource already initialized, reusing connection", describeDataSource(source));
      return source;
    }

    const start = Date.now();
    await source.initialize();
    const durationMs = Date.now() - start;

    logger.info("DataSource initialized successfully", {
      ...describeDataSource(source),
      duration_ms: durationMs,
    });
    return source;
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    logger.error("Failed to initialize DataSource", {
      ...describeDataSource(source),
      error: reason,
    });
    throw new AppError(
      500,
      `DataSource initialization failed: ${reason}`,
      "DATASOURCE_INIT_FAILED",
      { reason },
    );
  }
}

/**
 * Initialize the shared DataSource exactly once and reuse the in-flight or
 * resolved promise on subsequent calls. Safe to invoke from CLI scripts, the
 * HTTP server bootstrap, and workers concurrently.
 */
export async function initializeDataSource(): Promise<DataSource> {
  if (dataSource.isInitialized) {
    logger.debug("DataSource already initialized, reusing connection", describeDataSource(dataSource));
    return dataSource;
  }

  if (!initializationPromise) {
    initializationPromise = initializeInternal(dataSource).catch((error) => {
      initializationPromise = null;
      throw error;
    });
  }

  return initializationPromise;
}

/**
 * Close the shared DataSource if it is currently open. Safe to call multiple
 * times; missing connections are tolerated so this can be wired into shutdown
 * handlers without additional guards.
 */
export async function closeDataSource(): Promise<void> {
  if (!dataSource.isInitialized) {
    return;
  }

  try {
    await dataSource.destroy();
    logger.info("DataSource closed successfully", describeDataSource(dataSource));
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    logger.error("Failed to close DataSource", {
      ...describeDataSource(dataSource),
      error: reason,
    });
    throw new AppError(
      500,
      `DataSource shutdown failed: ${reason}`,
      "DATASOURCE_SHUTDOWN_FAILED",
      { reason },
    );
  } finally {
    initializationPromise = null;
  }
}

/**
 * Lightweight accessor for callers that only need a quick health probe without
 * paying the cost of `initialize()`. Returns `true` when the underlying
 * connection is already established.
 */
export function isDataSourceReady(): boolean {
  return dataSource.isInitialized;
}

// Default export preserved for the TypeORM CLI (`-d src/config/data-source.ts`).
export default dataSource;
