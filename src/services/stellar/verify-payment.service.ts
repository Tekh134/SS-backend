import { DataSource, Repository } from "typeorm";
import type { PaymentVerificationConfig } from "../../config/stellar";
import { Investment } from "../../models/Investment.model";
import { Transaction } from "../../models/Transaction.model";
import { InvestmentStatus, TransactionStatus, TransactionType } from "../../types/enums";
import { ServiceError } from "../../utils/service-error";
import type { AppLogger } from "../../observability/logger";
import { normalizeHorizonPayment, normalizeHorizonTransaction } from "../../utils/horizon-response";

type FetchLike = typeof fetch;
type SleepFn = (ms: number) => Promise<void>;

interface HorizonTransactionResponse {
  successful: boolean;
}

interface HorizonPaymentOperation {
  id?: string;
  type: string;
  asset_code?: string;
  asset_issuer?: string;
  amount?: string;
  to?: string;
}

interface HorizonOperationsResponse {
  _embedded?: {
    records?: HorizonPaymentOperation[];
  };
}

export interface PaymentVerificationInput {
  investmentId: string;
  stellarTxHash: string;
  operationIndex?: number;
}

export interface PaymentVerificationResult {
  outcome: "verified" | "already_verified";
  investmentId: string;
  stellarTxHash: string;
  operationIndex: number;
  transactionId: string;
  status: InvestmentStatus.CONFIRMED;
}

interface PaymentMatch {
  operationIndex: number;
  amount: string;
  destination: string;
  assetCode: string;
  assetIssuer: string;
}

interface InvestmentReader {
  findById(investmentId: string): Promise<Investment | null>;
}

interface PaymentVerificationUnitOfWork {
  findInvestmentByIdForUpdate(investmentId: string): Promise<Investment | null>;
  findTransactionsByInvestmentIdForUpdate(investmentId: string): Promise<Transaction[]>;
  saveInvestment(investment: Investment): Promise<Investment>;
  saveTransaction(transaction: Transaction): Promise<Transaction>;
  createTransaction(input: Partial<Transaction>): Transaction;
}

interface PaymentTransactionRunner {
  runInTransaction<T>(
    callback: (unitOfWork: PaymentVerificationUnitOfWork) => Promise<T>
  ): Promise<T>;
}

interface VerifyPaymentServiceDependencies {
  investmentReader: InvestmentReader;
  transactionRunner: PaymentTransactionRunner;
  config: PaymentVerificationConfig;
  fetchImplementation?: FetchLike;
  sleep?: SleepFn;
  logger?: AppLogger;
}

export class VerifyPaymentService {
  private readonly investmentReader: InvestmentReader;
  private readonly transactionRunner: PaymentTransactionRunner;
  private readonly config: PaymentVerificationConfig;
  private readonly fetchImplementation: FetchLike;
  private readonly sleep: SleepFn;
  private readonly logger: AppLogger;

  private static NOOP_LOGGER: AppLogger = {
    debug: () => undefined,
    info: () => undefined,
    warn: () => undefined,
    error: () => undefined,
    child: () => VerifyPaymentService.NOOP_LOGGER,
  };

  constructor(dependencies: VerifyPaymentServiceDependencies) {
    this.investmentReader = dependencies.investmentReader;
    this.transactionRunner = dependencies.transactionRunner;
    this.config = dependencies.config;
    this.fetchImplementation = dependencies.fetchImplementation ?? fetch;
    this.sleep =
      dependencies.sleep ?? ((ms: number) => new Promise((resolve) => setTimeout(resolve, ms)));
    this.logger = dependencies.logger ?? VerifyPaymentService.NOOP_LOGGER;
  }

  async verifyPayment(input: PaymentVerificationInput): Promise<PaymentVerificationResult> {
    const investment = await this.investmentReader.findById(input.investmentId);

    if (!investment) {
      throw new ServiceError("investment_not_found", "Investment not found.", 404);
    }

    if (investment.status === InvestmentStatus.CONFIRMED) {
      if (
        investment.transactionHash === input.stellarTxHash &&
        investment.stellarOperationIndex ===
          (input.operationIndex ?? investment.stellarOperationIndex)
      ) {
        return {
          outcome: "already_verified",
          investmentId: investment.id,
          stellarTxHash: input.stellarTxHash,
          operationIndex: investment.stellarOperationIndex ?? input.operationIndex ?? 0,
          transactionId: "",
          status: InvestmentStatus.CONFIRMED,
        };
      }

      throw new ServiceError(
        "reconciliation_conflict",
        "Investment is already confirmed with a different Stellar payment.",
        409
      );
    }

    const matchedPayment = await this.fetchAndValidatePayment(
      input.stellarTxHash,
      investment.investmentAmount,
      input.operationIndex
    );

    return this.transactionRunner.runInTransaction(async (unitOfWork) => {
      const lockedInvestment = await unitOfWork.findInvestmentByIdForUpdate(input.investmentId);

      if (!lockedInvestment) {
        throw new ServiceError("investment_not_found", "Investment not found.", 404);
      }

      const linkedTransactions = await unitOfWork.findTransactionsByInvestmentIdForUpdate(
        lockedInvestment.id
      );

      if (linkedTransactions.length > 1) {
        throw new ServiceError(
          "reconciliation_conflict",
          "Multiple transaction rows are linked to the same investment.",
          409
        );
      }

      if (lockedInvestment.status === InvestmentStatus.CONFIRMED) {
        const transaction = linkedTransactions[0];

        if (
          lockedInvestment.transactionHash === input.stellarTxHash &&
          lockedInvestment.stellarOperationIndex === matchedPayment.operationIndex
        ) {
          return {
            outcome: "already_verified" as const,
            investmentId: lockedInvestment.id,
            stellarTxHash: input.stellarTxHash,
            operationIndex: matchedPayment.operationIndex,
            transactionId: transaction?.id ?? "",
            status: InvestmentStatus.CONFIRMED as const,
          };
        }

        throw new ServiceError(
          "reconciliation_conflict",
          "Investment was confirmed by another transaction while verification was in progress.",
          409
        );
      }

      const existingTransaction = linkedTransactions[0];

      if (
        existingTransaction &&
        existingTransaction.stellarTxHash &&
        existingTransaction.stellarTxHash !== input.stellarTxHash
      ) {
        throw new ServiceError(
          "reconciliation_conflict",
          "Transaction row is already linked to a different Stellar hash.",
          409
        );
      }

      const transaction =
        existingTransaction ??
        unitOfWork.createTransaction({
          investmentId: lockedInvestment.id,

          invoiceId: lockedInvestment.invoiceId,
          userId: lockedInvestment.investorId,
          type: TransactionType.INVESTMENT,
          amount: lockedInvestment.investmentAmount,
          status: TransactionStatus.PENDING,
        });

      transaction.userId = lockedInvestment.investorId;

      transaction.invoiceId = lockedInvestment.invoiceId;

      transaction.investmentId = lockedInvestment.id;
      transaction.type = TransactionType.INVESTMENT;
      transaction.amount = lockedInvestment.investmentAmount;
      transaction.status = TransactionStatus.COMPLETED;
      transaction.stellarTxHash = input.stellarTxHash;
      transaction.stellarOperationIndex = matchedPayment.operationIndex;

      lockedInvestment.status = InvestmentStatus.CONFIRMED;
      lockedInvestment.transactionHash = input.stellarTxHash;
      lockedInvestment.stellarOperationIndex = matchedPayment.operationIndex;

      const savedTransaction = await unitOfWork.saveTransaction(transaction);
      await unitOfWork.saveInvestment(lockedInvestment);

      // Structured log for accepted funding
      this.logger.info("Investment funding accepted.", {
        event: "investment_funding_accepted",
        investment_id: lockedInvestment.id,
        invoice_id: lockedInvestment.invoiceId,
        wallet_id: lockedInvestment.investorId,
        transaction_id: savedTransaction.id,
        stellar_tx_hash: input.stellarTxHash,
        operation_index: matchedPayment.operationIndex,
        amount: lockedInvestment.investmentAmount,
      });

      return {
        outcome: "verified" as const,
        investmentId: lockedInvestment.id,
        stellarTxHash: input.stellarTxHash,
        operationIndex: matchedPayment.operationIndex,
        transactionId: savedTransaction.id,
        status: InvestmentStatus.CONFIRMED as const,
      };
    });
  }

  private async fetchAndValidatePayment(
    stellarTxHash: string,
    expectedAmount: string,
    operationIndex?: number
  ): Promise<PaymentMatch> {
    const transaction = normalizeHorizonTransaction(
      await this.fetchJson<HorizonTransactionResponse>(`/transactions/${stellarTxHash}`)
    );

    if (!transaction.successful) {
      throw new ServiceError("invalid_payment", "The Stellar transaction was not successful.", 422);
    }

    const operations = await this.fetchJson<HorizonOperationsResponse>(
      `/transactions/${stellarTxHash}/operations?limit=200&order=asc`
    );

    const paymentOperations = (operations._embedded?.records ?? [])
      .map((operation, index) => ({
        ...normalizeHorizonPayment(operation),
        operationIndex: index,
      }))
      .filter((operation) => operation.type === "payment");

    const matchingOperations = paymentOperations.filter((operation) => {
      if (operationIndex !== undefined && operation.operationIndex !== operationIndex) {
        return false;
      }

      return (
        operation.assetCode === this.config.usdcAssetCode &&
        operation.assetIssuer === this.config.usdcAssetIssuer &&
        operation.destination === this.config.escrowPublicKey &&
        operation.amount !== null &&
        amountsWithinDelta(operation.amount, expectedAmount, this.config.allowedAmountDelta)
      );
    });

    if (matchingOperations.length === 0) {
      throw new ServiceError(
        "invalid_payment",
        "No Stellar payment operation matched the expected asset, amount, and destination.",
        422
      );
    }

    if (matchingOperations.length > 1) {
      throw new ServiceError(
        "invalid_payment",
        "Multiple payment operations matched. Supply operationIndex to disambiguate.",
        422
      );
    }

    const match = matchingOperations[0];

    return {
      operationIndex: match.operationIndex,
      amount: match.amount ?? expectedAmount,
      destination: match.destination ?? "",
      assetCode: match.assetCode ?? "",
      assetIssuer: match.assetIssuer ?? "",
    };
  }

  private async fetchJson<T>(path: string): Promise<T> {
    const url = new URL(path, ensureTrailingSlash(this.config.horizonUrl)).toString();

    for (let attempt = 1; attempt <= this.config.retryAttempts; attempt += 1) {
      try {
        const response = await this.fetchImplementation(url, {
          method: "GET",
          headers: {
            Accept: "application/json",
          },
        });

        if (response.status === 404) {
          throw new ServiceError(
            "transaction_not_found",
            "The Stellar transaction could not be found in Horizon.",
            404
          );
        }

        if (response.status >= 500 || response.status === 429) {
          throw new RetryableHorizonError(`Transient Horizon response: ${response.status}`);
        }

        if (!response.ok) {
          throw new ServiceError(
            "horizon_request_failed",
            "Horizon rejected the verification request.",
            502
          );
        }

        return (await response.json()) as T;
      } catch (error) {
        if (error instanceof ServiceError) {
          throw error;
        }

        if (attempt === this.config.retryAttempts) {
          throw new ServiceError(
            "horizon_unavailable",
            "Horizon is temporarily unavailable. Please retry later.",
            503
          );
        }

        await this.sleep(this.config.retryBaseDelayMs * 2 ** (attempt - 1));
      }
    }

    throw new ServiceError(
      "horizon_unavailable",
      "Horizon is temporarily unavailable. Please retry later.",
      503
    );
  }
}

class TypeOrmInvestmentReader implements InvestmentReader {
  constructor(private readonly repository: Repository<Investment>) {}

  findById(investmentId: string): Promise<Investment | null> {
    return this.repository.findOne({
      where: { id: investmentId },
    });
  }
}

class TypeOrmTransactionRunner implements PaymentTransactionRunner {
  constructor(private readonly dataSource: DataSource) {}

  runInTransaction<T>(
    callback: (unitOfWork: PaymentVerificationUnitOfWork) => Promise<T>
  ): Promise<T> {
    return this.dataSource.transaction(async (manager) =>
      callback({
        findInvestmentByIdForUpdate: (investmentId: string) =>
          manager.getRepository(Investment).findOne({
            where: { id: investmentId },
          }),
        findTransactionsByInvestmentIdForUpdate: (investmentId: string) =>
          manager.getRepository(Transaction).find({
            where: { investmentId },
          }),
        saveInvestment: (investment: Investment) =>
          manager.getRepository(Investment).save(investment),
        saveTransaction: (transaction: Transaction) =>
          manager.getRepository(Transaction).save(transaction),
        createTransaction: (input: Partial<Transaction>) =>
          manager.getRepository(Transaction).create(input),
      })
    );
  }
}

export function createVerifyPaymentService(
  dataSource: DataSource,
  config: PaymentVerificationConfig
): VerifyPaymentService {
  return new VerifyPaymentService({
    investmentReader: new TypeOrmInvestmentReader(dataSource.getRepository(Investment)),
    transactionRunner: new TypeOrmTransactionRunner(dataSource),
    config,
  });
}

export class RetryableHorizonError extends Error {}

function ensureTrailingSlash(value: string): string {
  return value.endsWith("/") ? value : `${value}/`;
}

function amountsWithinDelta(actual: string, expected: string, delta: string): boolean {
  const scale = 7;
  const actualValue = toScaledBigInt(actual, scale);
  const expectedValue = toScaledBigInt(expected, scale);
  const deltaValue = toScaledBigInt(delta, scale);

  const difference =
    actualValue >= expectedValue ? actualValue - expectedValue : expectedValue - actualValue;

  return difference <= deltaValue;
}

function toScaledBigInt(value: string, scale: number): bigint {
  const normalized = value.trim();

  if (!/^-?\d+(\.\d+)?$/.test(normalized)) {
    throw new ServiceError("invalid_amount", `Invalid decimal amount: ${value}`, 500);
  }

  const isNegative = normalized.startsWith("-");
  const unsignedValue = isNegative ? normalized.slice(1) : normalized;
  const [wholePart, fractionalPart = ""] = unsignedValue.split(".");
  const paddedFraction = `${fractionalPart}${"0".repeat(scale)}`.slice(0, scale);
  const scaled = BigInt(`${wholePart}${paddedFraction}`);

  return isNegative ? -scaled : scaled;
}
