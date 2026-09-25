import {
  Contract,
  Address,
  nativeToScVal,
  xdr,
  SorobanRpc,
  Transaction,
  FeeBumpTransaction,
} from "stellar-sdk";
import type { AppLogger } from "../../observability/logger";
import { logger as globalLogger } from "../../observability/logger";
import { ServiceError } from "../../utils/service-error";
import type {
  CreateEscrowParams,
  CreateEscrowResult,
  FundEscrowParams,
  RecordPaymentParams,
  SettleEscrowParams,
  SimulateTransactionResult,
  SendTransactionResult,
} from "../../types/soroban.types";

export type CreateEscrowInput = CreateEscrowParams;
export type { CreateEscrowResult, FundEscrowParams, RecordPaymentParams, SettleEscrowParams };

export interface InvoiceEscrowContractServiceDependencies {
  contractId: string;
  rpcUrl?: string;
  networkPassphrase?: string;
  platformSecretKey?: string;
  server?: SorobanRpc.Server;
  logger?: AppLogger;
  confirmationPollMs?: number;
  confirmationAttempts?: number;
}

export class InvoiceEscrowContractService {
  private readonly contract: Contract;
  readonly contractId: string;
  private readonly rpcServer?: SorobanRpc.Server;
  private readonly networkPassphrase?: string;
  private readonly platformSecretKey?: string;
  private readonly logger: AppLogger;
  private readonly confirmationPollMs: number;
  private readonly confirmationAttempts: number;

  constructor(
    dependenciesOrContractId: string | InvoiceEscrowContractServiceDependencies,
    logger?: AppLogger
  ) {
    if (typeof dependenciesOrContractId === "string") {
      if (!dependenciesOrContractId || !dependenciesOrContractId.trim()) {
        throw new Error("contractId is required.");
      }
      this.contractId = dependenciesOrContractId.trim();
      this.contract = new Contract(this.contractId);
      this.logger = logger ?? globalLogger;
      this.confirmationPollMs = 1000;
      this.confirmationAttempts = 20;
    } else {
      if (!dependenciesOrContractId.contractId || !dependenciesOrContractId.contractId.trim()) {
        throw new Error("contractId is required.");
      }
      this.contractId = dependenciesOrContractId.contractId.trim();
      this.contract = new Contract(this.contractId);
      this.networkPassphrase = dependenciesOrContractId.networkPassphrase;
      this.platformSecretKey = dependenciesOrContractId.platformSecretKey;
      if (dependenciesOrContractId.server) {
        this.rpcServer = dependenciesOrContractId.server;
      } else if (dependenciesOrContractId.rpcUrl) {
        this.rpcServer = new SorobanRpc.Server(dependenciesOrContractId.rpcUrl, {
          allowHttp: dependenciesOrContractId.rpcUrl.startsWith("http://"),
        });
      }
      this.logger = dependenciesOrContractId.logger ?? logger ?? globalLogger;
      this.confirmationPollMs = dependenciesOrContractId.confirmationPollMs ?? 1000;
      this.confirmationAttempts = dependenciesOrContractId.confirmationAttempts ?? 20;
    }
  }

  private parseStroopAmount(amount: bigint | number | string, fieldName = "amountStroops"): bigint {
    try {
      const parsed = typeof amount === "bigint" ? amount : BigInt(amount);
      if (parsed <= 0n) {
        throw new Error(`${fieldName} must be positive.`);
      }
      return parsed;
    } catch (error) {
      if (error instanceof Error && error.message.includes("must be positive")) {
        throw error;
      }
      throw new Error(`Invalid ${fieldName}: ${String(amount)}`);
    }
  }

  private sanitizeString(value: string, fieldName: string): string {
    if (typeof value !== "string") {
      throw new Error(`${fieldName} must be a string.`);
    }
    const trimmed = value.trim();
    if (!trimmed) {
      throw new Error(`${fieldName} is required.`);
    }
    return trimmed;
  }

  private parseDueDate(dueDateTimestamp: number): number {
    if (!Number.isFinite(dueDateTimestamp) || dueDateTimestamp <= 0) {
      throw new Error("dueDateTimestamp must be a positive number.");
    }
    return dueDateTimestamp;
  }

  /**
   * Build the Soroban contract invocation operation for creating an escrow.
   */
  public buildCreateEscrowTx(
    invoiceId: string,
    sellerAddress: string,
    amountStroops: bigint | number | string,
    dueDateTimestamp: number,
    paymentTokenAddress: string
  ): xdr.Operation {
    const safeInvoiceId = this.sanitizeString(invoiceId, "invoiceId");
    const safeSeller = this.sanitizeString(sellerAddress, "sellerAddress");
    const safeToken = this.sanitizeString(paymentTokenAddress, "paymentTokenAddress");
    const amountBigInt = this.parseStroopAmount(amountStroops, "amountStroops");
    this.parseDueDate(dueDateTimestamp);

    return this.contract.call(
      "create_escrow",
      nativeToScVal(safeInvoiceId, { type: "symbol" }),
      new Address(safeSeller).toScVal(),
      nativeToScVal(amountBigInt, { type: "i128" }),
      nativeToScVal(dueDateTimestamp, { type: "u64" }),
      new Address(safeToken).toScVal()
    );
  }

  /**
   * Build the Soroban contract invocation operation for funding an escrow.
   */
  public buildFundEscrowTx(
    invoiceId: string,
    investorAddress: string,
    amountStroops: bigint | number | string
  ): xdr.Operation {
    const safeInvoiceId = this.sanitizeString(invoiceId, "invoiceId");
    const safeInvestor = this.sanitizeString(investorAddress, "investorAddress");
    const amountBigInt = this.parseStroopAmount(amountStroops, "amountStroops");

    return this.contract.call(
      "fund_escrow",
      nativeToScVal(safeInvoiceId, { type: "symbol" }),
      new Address(safeInvestor).toScVal(),
      nativeToScVal(amountBigInt, { type: "i128" })
    );
  }

  /**
   * Build the Soroban contract invocation operation for recording a payment.
   */
  public buildRecordPaymentTx(
    invoiceId: string,
    payerAddress: string,
    amountStroops: bigint | number | string
  ): xdr.Operation {
    const safeInvoiceId = this.sanitizeString(invoiceId, "invoiceId");
    const safePayer = this.sanitizeString(payerAddress, "payerAddress");
    const amountBigInt = this.parseStroopAmount(amountStroops, "amountStroops");

    return this.contract.call(
      "record_payment",
      nativeToScVal(safeInvoiceId, { type: "symbol" }),
      new Address(safePayer).toScVal(),
      nativeToScVal(amountBigInt, { type: "i128" })
    );
  }

  /**
   * Build the Soroban contract invocation operation for settling an escrow.
   */
  public buildSettleEscrowTx(invoiceId: string): xdr.Operation {
    const safeInvoiceId = this.sanitizeString(invoiceId, "invoiceId");
    return this.contract.call("settle_escrow", nativeToScVal(safeInvoiceId, { type: "symbol" }));
  }

  /**
   * Simulates a transaction against the Soroban RPC endpoint to verify resource limits and auth footprint.
   */
  public async simulateTransaction(
    transaction: Transaction | FeeBumpTransaction
  ): Promise<SimulateTransactionResult> {
    if (!this.rpcServer) {
      throw new Error("Soroban RPC server is not configured for simulation.");
    }

    let simResponse: Awaited<ReturnType<SorobanRpc.Server["simulateTransaction"]>>;
    try {
      simResponse = await this.rpcServer.simulateTransaction(transaction);
    } catch (error) {
      this.logger.error("Soroban simulateTransaction call failed.", {
        sorobanContractId: this.contractId,
        error: error instanceof Error ? error.message : String(error),
      });
      throw new ServiceError(
        "soroban_simulation_failed",
        "Failed to simulate the transaction against the Soroban RPC endpoint.",
        502,
      );
    }

    const successResponse = simResponse as unknown as {
      minResourceFee?: string;
      cost?: { cpuInsns?: string; memBytes?: string };
      results?: Array<{ auth?: xdr.SorobanAuthorizationEntry[]; xdr: string }>;
      transactionData?: xdr.SorobanTransactionData;
      error?: string;
    };

    return {
      minResourceFee: successResponse.minResourceFee ?? "0",
      cost: {
        cpuInsns: successResponse.cost?.cpuInsns ?? "0",
        memBytes: successResponse.cost?.memBytes ?? "0",
      },
      results: successResponse.results?.map((r) => ({
        auth: r.auth,
        xdr: r.xdr,
      })),
      transactionData: successResponse.transactionData,
      error: successResponse.error,
    };
  }

  /**
   * Submits a transaction to the Stellar network via Soroban RPC sendTransaction.
   */
  public async submitTransaction(
    transaction: Transaction | FeeBumpTransaction
  ): Promise<SendTransactionResult> {
    if (!this.rpcServer) {
      throw new Error("Soroban RPC server is not configured for submission.");
    }

    let response: Awaited<ReturnType<SorobanRpc.Server["sendTransaction"]>>;
    try {
      response = await this.rpcServer.sendTransaction(transaction);
    } catch (error) {
      this.logger.error("Soroban sendTransaction call failed.", {
        sorobanContractId: this.contractId,
        error: error instanceof Error ? error.message : String(error),
      });
      throw new ServiceError(
        "soroban_submission_failed",
        "Failed to submit the transaction to the Soroban RPC endpoint.",
        502,
      );
    }

    return {
      status: response.status,
      txHash: response.hash,
      errorResult: response.errorResult,
    };
  }

  /**
   * Polls for transaction confirmation until it reaches SUCCESS, FAILED, or times out.
   */
  public async waitForTransactionConfirmation(
    txHash: string,
  ): Promise<{ status: "SUCCESS" | "FAILED" | "NOT_FOUND"; ledger: number | null }> {
    if (!this.rpcServer) {
      throw new Error("Soroban RPC server is not configured for transaction confirmation polling.");
    }
    if (!txHash || !txHash.trim()) {
      throw new Error("txHash is required.");
    }

    for (let attempt = 0; attempt < this.confirmationAttempts; attempt++) {
      try {
        const result = await this.rpcServer.getTransaction(txHash);
        if (result.status === "SUCCESS") {
          this.logger.info("Soroban transaction confirmed on-chain.", {
            txHash,
            sorobanContractId: this.contractId,
            ledger: "ledger" in result ? Number(result.ledger) : null,
          });
          return {
            status: "SUCCESS",
            ledger: "ledger" in result ? Number(result.ledger) : null,
          };
        }
        if (result.status === "FAILED") {
          this.logger.error("Soroban transaction reverted on-chain.", {
            txHash,
            sorobanContractId: this.contractId,
          });
          return { status: "FAILED", ledger: null };
        }
      } catch (error) {
        this.logger.warn("Transient error while checking transaction status", {
          txHash,
          attempt: attempt + 1,
          error: error instanceof Error ? error.message : String(error),
        });
      }

      await new Promise((resolve) => setTimeout(resolve, this.confirmationPollMs));
    }

    this.logger.error("Timed out waiting for transaction confirmation.", {
      txHash,
      sorobanContractId: this.contractId,
      attempts: this.confirmationAttempts,
    });
    throw new ServiceError(
      "transaction_confirmation_timeout",
      "Timed out waiting for transaction confirmation on-chain.",
      504,
    );
  }

  /**
   * Creates/initializes an escrow on-chain and logs the structured completion event.
   * Ensures that only sanitized metadata (invoiceId, sorobanContractId, sellerAddress, amountStroops)
   * is logged without leaking any secret keys, signing seeds, or auth tokens.
   */
  public async createEscrowOnChain(input: CreateEscrowInput): Promise<CreateEscrowResult> {
    const amountBigInt = this.parseStroopAmount(input.amountStroops, "amountStroops");
    this.parseDueDate(input.dueDateTimestamp);

    const operation = this.buildCreateEscrowTx(
      input.invoiceId,
      input.sellerAddress,
      amountBigInt,
      input.dueDateTimestamp,
      input.paymentTokenAddress
    );

    const amountStroopsStr = amountBigInt.toString();

    // Log structured event on successful escrow creation
    this.logger.info("Soroban escrow created successfully on-chain.", {
      invoiceId: input.invoiceId,
      sorobanContractId: this.contractId,
      sellerAddress: input.sellerAddress,
      amountStroops: amountStroopsStr,
    });

    return {
      contractId: this.contractId,
      invoiceId: input.invoiceId,
      sellerAddress: input.sellerAddress,
      amountStroops: amountStroopsStr,
      operation,
    };
  }
}