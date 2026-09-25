import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  Index,
  BeforeInsert,
  BeforeUpdate,
} from "typeorm";
import Decimal from "decimal.js";
import { TransactionType, TransactionStatus } from "../types/enums";
import type { Investment } from "./Investment.model";
import type { Invoice } from "./Invoice.model";
import { AppError } from "../utils/http-error";
import { logger } from "../observability/logger";

@Entity("transactions")
@Index("idx_transactions_status_type_timestamp", ["status", "type", "timestamp"])
@Index("idx_transactions_user_id_timestamp", ["userId", "timestamp"])
@Index("idx_transactions_user_status_timestamp", ["userId", "status", "timestamp"])
@Index("idx_transactions_investment_status", ["investmentId", "status"])
@Index("idx_transactions_invoice_status", ["invoiceId", "status"])
export class Transaction {
  @PrimaryGeneratedColumn("uuid")
  id!: string;

  @Column({ name: "user_id", type: "uuid" })
  @Index("idx_transactions_user_id")
  userId!: string;

  @Column({ name: "investment_id", type: "uuid", nullable: true })
  @Index("idx_transactions_investment_id")
  investmentId!: string | null;

  @Column({ name: "invoice_id", type: "uuid", nullable: true })
  @Index("idx_transactions_invoice_id")
  invoiceId!: string | null;

  @Column({
    type: "enum",
    enum: TransactionType,
  })
  @Index("idx_transactions_type")
  type!: TransactionType;

  @Column({ type: "decimal", precision: 18, scale: 4 })
  amount!: string;

  @Column({ name: "stellar_tx_hash", type: "varchar", length: 64, nullable: true })
  @Index("idx_transactions_stellar_tx_hash")
  stellarTxHash!: string | null;

  @Column({ name: "stellar_operation_index", type: "integer", nullable: true })
  stellarOperationIndex!: number | null;

  @Column({
    type: "enum",
    enum: TransactionStatus,
    default: TransactionStatus.PENDING,
  })
  @Index("idx_transactions_status")
  status!: TransactionStatus;

  @Column({ type: "timestamptz", default: () => "CURRENT_TIMESTAMP" })
  timestamp!: Date;

  @ManyToOne("User", "transactions", { onDelete: "CASCADE" })
  @JoinColumn({ name: "user_id" })
  user!: import("./User.model").User;

  @ManyToOne("Investment", "transactions", { onDelete: "SET NULL", nullable: true })
  @JoinColumn({ name: "investment_id" })
  investment!: Investment | null;

  @ManyToOne("Invoice", "transactions", { onDelete: "SET NULL", nullable: true })
  @JoinColumn({ name: "invoice_id" })
  invoice!: Invoice | null;

  @BeforeInsert()
  @BeforeUpdate()
  sanitizeTransactionData(): void {
    try {
      if (this.amount) {
        const parsed = new Decimal(this.amount);
        if (parsed.isNegative()) {
          throw new Error("Transaction amount cannot be negative");
        }
        this.amount = parsed.toFixed(4);
      }
      if (this.stellarTxHash) {
        this.stellarTxHash = this.stellarTxHash.trim().toUpperCase();
      }
    } catch (error) {
      logger.error("Failed to sanitize transaction data", {
        transactionId: this.id,
        userId: this.userId,
        error: error instanceof Error ? error.message : String(error),
      });
      throw new AppError(400, "Invalid transaction amount formatting", "INVALID_TRANSACTION_AMOUNT");
    }
  }

  markCompleted(stellarTxHash?: string, operationIndex?: number): void {
    if (stellarTxHash) {
      this.stellarTxHash = stellarTxHash;
    }
    if (operationIndex !== undefined) {
      this.stellarOperationIndex = operationIndex;
    }
    this.status = TransactionStatus.COMPLETED;
    this.sanitizeTransactionData();
  }

  markFailed(reason?: string): void {
    this.status = TransactionStatus.FAILED;
    logger.warn("Transaction marked as failed", {
      transactionId: this.id,
      userId: this.userId,
      reason,
    });
  }

  static async processBatchTransactions(transactions: Transaction[]): Promise<Transaction[]> {
    try {
      logger.info("Processing transaction batch", { count: transactions.length });
      for (const tx of transactions) {
        tx.sanitizeTransactionData();
      }
      return transactions;
    } catch (error) {
      logger.error("Failed to process transaction batch", {
        error: error instanceof Error ? error.message : String(error),
      });
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError(500, "Processing transaction batch failed", "TRANSACTION_BATCH_FAILED", error);
    }
  }
}
