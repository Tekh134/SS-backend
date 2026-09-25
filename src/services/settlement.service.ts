import { DataSource, EntityManager } from "typeorm";
import { Decimal } from "decimal.js";
import { Invoice } from "../models/Invoice.model";
import { Investment } from "../models/Investment.model";
import { InvoiceStatus, InvestmentStatus } from "../types/enums";
import { TransactionStatus, TransactionType } from "../types/enums";
import { Transaction } from "../models/Transaction.model";
import { ServiceError } from "../utils/service-error";
import { computeInvestorReturn } from "../lib/investor-return";
import { decimalStringToScaledBigInt, scaledBigIntToDecimalString } from "../lib/decimal-bigint";
import { logInvoiceTransition } from "../lib/invoice-lifecycle-log";
import { logSettlementCompletion } from "../lib/settlement-completion-log";
import { logger } from "../observability/logger";
import {
  logSettlementStart,
  logSettlementFailure,
  logSettlementSuccess,
} from "../lib/settlement-observability";
import type { PaymentDistributorContractService } from "./stellar/payment-distributor-contract.service";

// settlement.service.ts stores/computes amounts as decimal strings scaled by
// 10^4 (see decimal-bigint.ts), while stroopsToXlm expects a stroops count
// (10^7 scale). Multiplying by 10^3 converts between the two without any
// loss of precision, since 7 - 4 = 3.
const DECIMAL_SCALE_TO_STROOP_FACTOR = 10n ** 3n;

export interface SettleInvoiceInput {
  invoiceId: string;
  proceeds: string;
  actorWallet: string;
}

export interface PaymentDistributorSettlementConfig {
  feeRecipient: string;
  feeBps: number;
}

export interface InvestorSettlement {
  investmentId: string;
  investorId: string;
  investmentAmount: string;
  actualReturn: string;
}

export interface SettleInvoiceResult {
  invoiceId: string;
  status: InvoiceStatus.SETTLED;
  proceeds: string;
  settlements: InvestorSettlement[];
  distributionTransactionHash?: string;
}

export class SettlementService {
  constructor(
    private readonly dataSource: DataSource,
    private readonly paymentDistributor?: PaymentDistributorContractService,
    private readonly distributorConfig?: PaymentDistributorSettlementConfig
  ) {}

  /**
   * Settles a funded invoice by distributing proceeds to each investor
   * pro-rata to their share of the invoice's face value.
   */
  async settleInvoice(input: SettleInvoiceInput): Promise<SettleInvoiceResult> {
    const { invoiceId, proceeds: proceedsInput, actorWallet } = input;

    const proceeds = new Decimal(proceedsInput);
    if (proceeds.isNegative() || proceeds.isZero()) {
      throw new ServiceError("INVALID_PROCEEDS", "Settlement proceeds must be greater than zero");
    }

    const startedAt = Date.now();
    const startedAtIso = new Date(startedAt).toISOString();
    logSettlementStart(logger, { invoiceId, actorWallet, startedAt: startedAtIso });

    try {
      return await this.dataSource.transaction(
        async (transactionalEntityManager: EntityManager) => {
          // 1. Lock the invoice row for update (if supported by the driver).
          //    SQLite does not support row-level locking, so we fall back to a plain read.
          let invoice: Invoice | null;
          try {
            invoice = await transactionalEntityManager
              .createQueryBuilder(Invoice, "invoice")
              .setLock("pessimistic_write")
              .where("invoice.id = :id", { id: invoiceId })
              .getOne();
          } catch {
            invoice = await transactionalEntityManager
              .createQueryBuilder(Invoice, "invoice")
              .where("invoice.id = :id", { id: invoiceId })
              .getOne();
          }

          if (!invoice) {
            throw new ServiceError("INVOICE_NOT_FOUND", `Invoice ${invoiceId} not found`);
          }

          // 2. Validate invoice status
          if (invoice.status !== InvoiceStatus.FUNDED) {
            throw new ServiceError(
              "INVALID_INVOICE_STATUS",
              `Cannot settle an invoice with status ${invoice.status}`
            );
          }

          // 3. Fetch confirmed investments for this invoice
          const investments = await transactionalEntityManager
            .createQueryBuilder(Investment, "investment")
            .leftJoinAndSelect("investment.investor", "investor")
            .where("investment.invoiceId = :invoiceId", { invoiceId })
            .andWhere("investment.status = :status", { status: InvestmentStatus.CONFIRMED })
            .getMany();

          if (investments.length === 0) {
            throw new ServiceError(
              "NO_CONFIRMED_INVESTMENTS",
              "Invoice has no confirmed investments to settle"
            );
          }

          // 4. Distribute proceeds pro-rata to each investor's share of the total funded amount
          const totalFunded = investments.reduce(
            (sum, investment) => sum.plus(new Decimal(investment.investmentAmount)),
            new Decimal(0)
          );
          const totalFundedScaled = decimalStringToScaledBigInt(totalFunded.toFixed(4));
          const proceedsScaled = decimalStringToScaledBigInt(proceeds.toFixed(4));
          const feeScaled = this.distributorConfig
            ? (proceedsScaled * BigInt(this.distributorConfig.feeBps)) / 10_000n
            : 0n;
          const distributableScaled = proceedsScaled - feeScaled;
          const settlements: InvestorSettlement[] = [];
          let distributionTransactionHash: string | undefined;

          if (this.paymentDistributor) {
            if (!this.distributorConfig) {
              throw new ServiceError(
                "DISTRIBUTOR_CONFIGURATION_MISSING",
                "Payment distributor fee configuration is required"
              );
            }
            const distribution = await this.paymentDistributor.distributePayouts({
              invoiceId: invoice.id,
              totalAmountStroops: proceedsScaled * DECIMAL_SCALE_TO_STROOP_FACTOR,
              feeRecipient: this.distributorConfig.feeRecipient,
              feeBps: this.distributorConfig.feeBps,
              recipients: investments.map((investment) => ({
                address: investment.investor?.stellarAddress ?? investment.investorId,
                amountStroops:
                  computeInvestorReturn(
                    decimalStringToScaledBigInt(investment.investmentAmount),
                    totalFundedScaled,
                    distributableScaled
                  ) * DECIMAL_SCALE_TO_STROOP_FACTOR,
              })),
            });
            distributionTransactionHash = distribution.transactionHash;
            await transactionalEntityManager.save(
              Transaction,
              transactionalEntityManager.create(Transaction, {
                userId: invoice.sellerId,
                invoiceId: invoice.id,
                investmentId: null,
                type: TransactionType.PAYMENT,
                amount: proceeds.toFixed(4),
                stellarTxHash: distribution.transactionHash,
                stellarOperationIndex: 0,
                status: TransactionStatus.COMPLETED,
              })
            );
          }

          for (const investment of investments) {
            const investmentAmountScaled = decimalStringToScaledBigInt(investment.investmentAmount);
            const actualReturnScaled = computeInvestorReturn(
              investmentAmountScaled,
              totalFundedScaled,
              distributableScaled
            );

            investment.actualReturn = scaledBigIntToDecimalString(actualReturnScaled);
            investment.status = InvestmentStatus.SETTLED;
            await transactionalEntityManager.save(Investment, investment);

            settlements.push({
              investmentId: investment.id,
              investorId: investment.investorId,
              investmentAmount: investment.investmentAmount,
              actualReturn: investment.actualReturn,
            });
          }

          invoice.status = InvoiceStatus.SETTLED;
          await transactionalEntityManager.save(Invoice, invoice);

          const durationMs = Date.now() - startedAt;
          logSettlementSuccess(logger, {
            invoiceId,
            durationMs,
            distributionTxHash: distributionTransactionHash,
            totalProceedsStroops: proceedsScaled,
            investorCount: settlements.length,
          });

          return {
            invoiceId,
            status: InvoiceStatus.SETTLED,
            proceeds: proceeds.toFixed(4),
            settlements,
            distributionTransactionHash,
          };
        }
      );
    } catch (err) {
      const durationMs = Date.now() - startedAt;
      const category = err instanceof ServiceError ? err.code : "UNKNOWN_ERROR";
      const retryable = !(err instanceof ServiceError) || err.statusCode >= 500;

      logSettlementFailure(logger, {
        invoiceId,
        error: err,
        durationMs,
        distributionTxHash: undefined,
        category,
        retryable,
      });

      throw err;
    }
  }
}

export function createSettlementService(
  dataSource: DataSource,
  paymentDistributor?: PaymentDistributorContractService,
  distributorConfig?: PaymentDistributorSettlementConfig
): SettlementService {
  return new SettlementService(dataSource, paymentDistributor, distributorConfig);
}