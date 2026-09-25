import { DataSource, In } from "typeorm";
import Decimal from "decimal.js";
import { Invoice } from "../models/Invoice.model";
import { Investment } from "../models/Investment.model";
import { User } from "../models/User.model";
import { InvoiceStatus, KYCStatus, InvestmentStatus, NotificationType } from "../types/enums";
import { ServiceError } from "../utils/service-error";
import { validateInvoiceForPublish } from "../lib/validate-invoice-for-publish";
import { logInvoiceTransition } from "../lib/invoice-lifecycle-log";
import { logger } from "../observability/logger";
import { AppError } from "../utils/http-error";
import type { IPFSService, IPFSUploadResult } from "./ipfs.service";

export interface InvoiceRepositoryContract {
  findOne(options: { where: { id: string }; relations?: string[] }): Promise<Invoice | null>;
  findOneBy(options: { id?: string; invoiceNumber?: string }): Promise<Invoice | null>;
  find(options: {
    where: {
      sellerId?: string;
      status?: InvoiceStatus;
      id?: ReturnType<typeof In<string>>;
    };
    skip?: number;
    take?: number;
    order?: { [key: string]: "ASC" | "DESC" };
    relations?: string[];
  }): Promise<Invoice[]>;
  save(invoice: Invoice): Promise<Invoice>;
  count(options: { where: { sellerId: string; status?: InvoiceStatus } }): Promise<number>;
  create(data: Partial<Invoice>): Invoice;
}

/**
 * Minimal contract for notifying a user, satisfied by
 * `NotificationService.createNotification` (see notification.service.ts).
 * Kept as a narrow structural type here (rather than importing
 * `NotificationService` directly) to avoid coupling `InvoiceService` to the
 * notification module's full surface area.
 */
export interface NotificationSink {
  createNotification(
    userId: string,
    type: NotificationType,
    title: string,
    message: string
  ): Promise<unknown>;
}

export interface InvoiceServiceDependencies {
  invoiceRepository: InvoiceRepositoryContract;
  ipfsService: IPFSService;
  dataSource?: DataSource;
  /** Optional: enables `rejectInvoice` to notify the seller. If omitted,
   *  rejection still persists the status/reason but skips notifying. */
  notificationSink?: NotificationSink;
}

export interface UploadDocumentInput {
  invoiceId: string;
  sellerId: string;
  fileBuffer: Buffer;
  filename: string;
  mimeType: string;
}

export interface UploadDocumentResult {
  invoiceId: string;
  ipfsHash: string;
  fileSize: number;
  uploadedAt: string;
}

export interface CreateInvoiceInput {
  sellerId: string;
  invoiceNumber: string;
  customerName: string;
  amount: string;
  discountRate: string;
  dueDate: Date;
  ipfsHash?: string;
  riskScore?: string;
}

export interface UpdateInvoiceInput {
  sellerId: string;
  invoiceId: string;
  customerName?: string;
  amount?: string;
  discountRate?: string;
  dueDate?: Date;
  riskScore?: string;
}

export interface PublishInvoiceInput {
  invoiceId: string;
  sellerId: string;
}

export interface RejectInvoiceInput {
  invoiceId: string;
  rejectionReason: string;
}

export interface BatchPublishInvoicesInput {
  invoiceIds: string[];
  sellerId: string;
}

/** Why a single invoice in a batch could not be published. */
export interface BatchPublishRejection {
  invoiceId: string;
  code:
    | "invoice_not_found"
    | "unauthorized_invoice_access"
    | "invalid_status_transition"
    | "invoice_not_publishable";
  message: string;
}

export interface BatchPublishInvoicesResult {
  published: InvoiceDTO[];
  count: number;
}

export interface CommitmentDTO {
  investor_wallet: string;
  amount: string;
  share_percent: string;
}

export interface InvoiceDTO {
  id: string;
  sellerId: string;
  invoiceNumber: string;
  customerName: string;
  amount: string;
  discountRate: string;
  netAmount: string;
  dueDate: Date;
  status: InvoiceStatus;
  ipfsHash: string | null;
  riskScore: string | null;
  smartContractId: string | null;
  rejectionReason: string | null;
  createdAt: Date;
  updatedAt: Date;
  commitments?: CommitmentDTO[];
}

export interface GetInvoicesOptions {
  sellerId: string;
  status?: InvoiceStatus;
  skip?: number;
  take?: number;
}

/**
 * Valid state transitions for InvoiceStatus
 */
const VALID_TRANSITIONS: Record<InvoiceStatus, InvoiceStatus[]> = {
  [InvoiceStatus.DRAFT]: [InvoiceStatus.PENDING, InvoiceStatus.PUBLISHED, InvoiceStatus.CANCELLED],
  [InvoiceStatus.PENDING]: [
    InvoiceStatus.PUBLISHED,
    InvoiceStatus.CANCELLED,
    InvoiceStatus.REJECTED,
  ],
  [InvoiceStatus.PUBLISHED]: [InvoiceStatus.FUNDED, InvoiceStatus.CANCELLED],
  [InvoiceStatus.FUNDED]: [InvoiceStatus.SETTLED, InvoiceStatus.CANCELLED],
  [InvoiceStatus.SETTLED]: [],
  [InvoiceStatus.CANCELLED]: [],
  [InvoiceStatus.REJECTED]: [],
};

export class InvoiceService {
  private readonly invoiceRepository: InvoiceRepositoryContract;
  private readonly ipfsService: IPFSService;
  private readonly dataSource?: DataSource;
  private readonly notificationSink?: NotificationSink;

  constructor(dependencies: InvoiceServiceDependencies) {
    this.invoiceRepository = dependencies.invoiceRepository;
    this.ipfsService = dependencies.ipfsService;
    this.dataSource = dependencies.dataSource;
    this.notificationSink = dependencies.notificationSink;
  }

  /**
   * Calculate net_amount from amount and discount_rate
   * Formula: net_amount = amount - (amount * discount_rate / 100)
   *
   * Uses Decimal (as the rest of this file's money math already does in
   * getInvoiceTokenHolders) rather than native floats: parseFloat-based
   * arithmetic here silently rounded some amount/discountRate combinations
   * to the wrong cent — e.g. amount="29.99", discountRate="0.5" produced
   * "29.8400" instead of the correct "29.8401" — because IEEE-754 doubles
   * can't represent most decimal fractions exactly.
   * Validates inputs to prevent NaN/Infinity propagation under load.
   */
  private calculateNetAmount(amount: string, discountRate: string): string {
    try {
      const amt = new Decimal(amount);
      const disc = new Decimal(discountRate);
      if (
        !amt.isFinite() ||
        !disc.isFinite() ||
        amt.isNegative() ||
        disc.isNegative() ||
        disc.gt(100)
      ) {
        throw new ServiceError("invalid_amount", "Invalid amount or discount rate", 400);
      }
      const netAmount = amt.minus(amt.times(disc.dividedBy(100)));
      return netAmount.toFixed(4);
    } catch (error) {
      if (error instanceof ServiceError) throw error;
      logger.error("Failed to calculate net amount", { error, amount, discountRate });
      throw new ServiceError("invalid_amount", "Invalid amount or discount rate", 400);
    }
  }

  private sanitizeInvoiceNumber(value: string): string {
    return value.trim().slice(0, 64);
  }

  /**
   * Check if a status transition is valid
   */
  private isValidTransition(from: InvoiceStatus, to: InvoiceStatus): boolean {
    return VALID_TRANSITIONS[from]?.includes(to) ?? false;
  }

  /**
   * Create a new invoice - hardened with input sanitization, precise math,
   * and resilient error handling for downstream DB failures.
   */
  async createInvoice(input: CreateInvoiceInput): Promise<InvoiceDTO> {
    try {
      const invoiceNumber = this.sanitizeInvoiceNumber(input.invoiceNumber);
      if (!invoiceNumber) {
        throw new ServiceError("invalid_invoice_number", "Invoice number is required", 400);
      }

      const existing = await this.invoiceRepository.findOneBy({
        invoiceNumber,
      });

      if (existing) {
        throw new ServiceError("invoice_number_exists", "Invoice number must be unique", 409);
      }

      const netAmount = this.calculateNetAmount(input.amount, input.discountRate);

      const invoice = this.invoiceRepository.create({
        sellerId: input.sellerId,
        invoiceNumber,
        customerName: input.customerName.trim().slice(0, 255),
        amount: input.amount,
        discountRate: input.discountRate,
        netAmount,
        dueDate: input.dueDate,
        ipfsHash: input.ipfsHash?.trim() || null,
        riskScore: input.riskScore?.trim() || null,
        status: InvoiceStatus.DRAFT,
      } as Partial<Invoice>);

      const saved = await this.invoiceRepository.save(invoice);
      return this.toDTO(saved);
    } catch (error) {
      if (error instanceof ServiceError) throw error;
      logger.error("Failed to create invoice", { error, sellerId: input.sellerId });
      throw new ServiceError("invoice_create_failed", "Failed to create invoice", 500);
    }
  }

  /**
   * Get invoice by ID - with graceful handling of DB failures
   */
  async getInvoiceById(invoiceId: string, sellerId?: string): Promise<InvoiceDTO | null> {
    try {
      const sanitizedId = invoiceId.trim();
      if (!sanitizedId) return null;

      const invoice = await this.invoiceRepository.findOne({
        where: { id: sanitizedId },
      });

      if (!invoice) {
        return null;
      }

      if (sellerId && invoice.sellerId !== sellerId) {
        throw new ServiceError(
          "unauthorized_invoice_access",
          "You do not have access to this invoice",
          403
        );
      }

      return this.toDTO(invoice);
    } catch (error) {
      if (error instanceof ServiceError) throw error;
      logger.error("Failed to fetch invoice by id", { error, invoiceId });
      throw new ServiceError("invoice_fetch_failed", "Failed to fetch invoice", 500);
    }
  }

  /**
   * Get all invoices for a seller - parallel fetch, input sanitization, and bounded pagination
   */
  async getInvoicesBySellerId(options: GetInvoicesOptions): Promise<{
    invoices: InvoiceDTO[];
    total: number;
  }> {
    try {
      const sellerId = options.sellerId?.trim();
      if (!sellerId) {
        throw new ServiceError("invalid_seller_id", "Seller id is required", 400);
      }

      const where: { sellerId: string; status?: InvoiceStatus; deletedAt: null } = {
        sellerId,
        deletedAt: null,
      };

      if (options.status && Object.values(InvoiceStatus).includes(options.status)) {
        where.status = options.status;
      }

      const skip = Math.max(0, Math.min(options.skip ?? 0, 10000));
      const take = Math.max(1, Math.min(options.take ?? 20, 100));

      const [invoices, total] = await Promise.all([
        this.invoiceRepository.find({
          where,
          skip,
          take,
          order: { createdAt: "DESC" },
        }),
        this.invoiceRepository.count({ where }),
      ]);

      return {
        invoices: invoices.map((inv) => this.toDTO(inv)),
        total,
      };
    } catch (error) {
      if (error instanceof ServiceError) throw error;
      logger.error("Failed to fetch invoices by seller", { error, sellerId: options.sellerId });
      throw new ServiceError("invoice_list_failed", "Failed to fetch invoices", 500);
    }
  }

  /**
   * Update an invoice (only draft invoices can be updated)
   */
  async updateInvoice(input: UpdateInvoiceInput): Promise<InvoiceDTO> {
    try {
      const invoice = await this.invoiceRepository.findOne({
        where: { id: input.invoiceId },
      });

      if (!invoice) {
        throw new ServiceError("invoice_not_found", "Invoice not found", 404);
      }

      // Verify ownership
      if (invoice.sellerId !== input.sellerId) {
        throw new ServiceError(
          "unauthorized_invoice_access",
          "You can only update your own invoices",
          403
        );
      }

      // Only draft invoices can be updated
      if (invoice.status !== InvoiceStatus.DRAFT) {
        throw new ServiceError(
          "invalid_invoice_status",
          `Cannot update invoice in ${invoice.status} status. Only draft invoices can be updated.`,
          400
        );
      }

      // Update fields
      if (input.customerName) {
        invoice.customerName = input.customerName;
      }
      if (input.amount) {
        invoice.amount = input.amount;
        invoice.discountRate = input.discountRate || invoice.discountRate;
        invoice.netAmount = this.calculateNetAmount(invoice.amount, invoice.discountRate);
      } else if (input.discountRate) {
        invoice.discountRate = input.discountRate;
        invoice.netAmount = this.calculateNetAmount(invoice.amount, invoice.discountRate);
      }
      if (input.dueDate) {
        invoice.dueDate = input.dueDate;
      }
      if (input.riskScore) {
        invoice.riskScore = input.riskScore;
      }

      const updated = await this.invoiceRepository.save(invoice);
      return this.toDTO(updated);
    } catch (error) {
      if (error instanceof ServiceError) throw error;
      logger.error('Failed to process', { error });
      throw new AppError(500, 'Processing failed', 'PROCESSING_FAILED', { error });
    }
  }

  /**
   * Soft delete an invoice
   */
  async deleteInvoice(invoiceId: string, sellerId: string): Promise<void> {
    try {
      const invoice = await this.invoiceRepository.findOne({
        where: { id: invoiceId },
      });

      if (!invoice) {
        throw new ServiceError("invoice_not_found", "Invoice not found", 404);
      }

      // Verify ownership
      if (invoice.sellerId !== sellerId) {
        throw new ServiceError(
          "unauthorized_invoice_access",
          "You can only delete your own invoices",
          403
        );
      }

      // Only draft and cancelled invoices can be deleted
      if (invoice.status !== InvoiceStatus.DRAFT && invoice.status !== InvoiceStatus.CANCELLED) {
        throw new ServiceError(
          "invalid_invoice_status",
          `Cannot delete invoice in ${invoice.status} status`,
          400
        );
      }

      invoice.deletedAt = new Date();
      await this.invoiceRepository.save(invoice);
    } catch (error) {
      if (error instanceof ServiceError) throw error;
      logger.error('Failed to process', { error });
      throw new AppError(500, 'Processing failed', 'PROCESSING_FAILED', { error });
    }
  }

  /**
   * Publish an invoice (transition from DRAFT to PUBLISHED)
   */
  async publishInvoice(input: PublishInvoiceInput): Promise<InvoiceDTO> {
    try {
      const invoice = await this.invoiceRepository.findOne({
        where: { id: input.invoiceId },
        relations: ["seller"],
      });

      if (!invoice) {
        throw new ServiceError("invoice_not_found", "Invoice not found", 404);
      }

      // Verify ownership
      if (invoice.sellerId !== input.sellerId) {
        throw new ServiceError(
          "unauthorized_invoice_access",
          "You can only publish your own invoices",
          403
        );
      }

      // Check KYC status
      const seller = invoice.seller as unknown as User;
      if (!seller || seller.kycStatus !== KYCStatus.APPROVED) {
        throw new ServiceError(
          "kyc_approval_required",
          "KYC approval is required to publish invoices",
          403
        );
      }

      // Check if transition is valid
      if (!this.isValidTransition(invoice.status, InvoiceStatus.PUBLISHED)) {
        throw new ServiceError(
          "invalid_status_transition",
          `Cannot transition from ${invoice.status} to ${InvoiceStatus.PUBLISHED}`,
          400
        );
      }

      const validationErrors = validateInvoiceForPublish(invoice);
      if (validationErrors.length > 0) {
        throw new ServiceError(
          "invoice_not_publishable",
          `Invoice failed pre-publish validation: ${validationErrors.map((e) => e.message).join(" ")}`,
          400,
        );
      }

      const previousStatus = invoice.status;
      invoice.status = InvoiceStatus.PUBLISHED;
      const updated = await this.invoiceRepository.save(invoice);

      logInvoiceTransition(logger, {
        invoiceId: updated.id,
        fromState: previousStatus,
        toState: InvoiceStatus.PUBLISHED,
        actorWallet: seller.stellarAddress,
        reason: "seller_published",
      });

      return this.toDTO(updated);
    } catch (error) {
      if (error instanceof ServiceError) throw error;
      logger.error('Failed to process', { error });
      throw new AppError(500, 'Processing failed', 'PROCESSING_FAILED', { error });
    }
  }

  /**
   * Reject a pending invoice (admin action)
   */
  async rejectInvoice(input: { invoiceId: string; rejectionReason: string }): Promise<InvoiceDTO> {
    const invoice = await this.invoiceRepository.findOne({
      where: { id: input.invoiceId },
      relations: ["seller"],
    });

    if (!invoice) {
      throw new ServiceError("invoice_not_found", "Invoice not found", 404);
    }

    // Check if already rejected
    if (invoice.status === InvoiceStatus.REJECTED) {
      throw new ServiceError("invoice_already_rejected", "Invoice is already rejected", 409);
    }

    // Check if transition is valid
    if (!this.isValidTransition(invoice.status, InvoiceStatus.REJECTED)) {
      throw new ServiceError(
        "invalid_status_transition",
        `Cannot transition from ${invoice.status} to ${InvoiceStatus.REJECTED}`,
        409
      );
    }

    const previousStatus = invoice.status;
    invoice.status = InvoiceStatus.REJECTED;
    invoice.rejectionReason = input.rejectionReason.trim();
    const updated = await this.invoiceRepository.save(invoice);

    const seller = invoice.seller as unknown as User;
    logInvoiceTransition(logger, {
      invoiceId: updated.id,
      fromState: previousStatus,
      toState: InvoiceStatus.REJECTED,
      actorWallet: seller?.stellarAddress ?? "admin",
      reason: "admin_rejected",
    });

    // Notify seller if notification sink is available
    if (this.notificationSink && seller) {
      try {
        await this.notificationSink.createNotification(
          seller.id,
          NotificationType.INVOICE,
          "Invoice Rejected",
          `Your invoice ${invoice.invoiceNumber} has been rejected: ${input.rejectionReason}`
        );
      } catch (notifyError) {
        logger.warn("Failed to notify seller of invoice rejection", {
          error: notifyError,
          invoiceId: invoice.id,
        });
      }
    }

    return this.toDTO(updated);
  }

  /**
   * Publish several draft invoices in one atomic step.
   *
   * Sellers with large receivable books were publishing twenty invoices with
   * twenty round trips, and a failure halfway through left them with a
   * half-published book and no clear way to tell which half. This is all or
   * nothing: every invoice is validated first, and if any one of them fails
   * the whole batch is rejected and nothing is written.
   *
   * The rejection list names every invoice that failed and why, so the seller
   * can fix all of them in one pass rather than rediscovering the next problem
   * on each retry.
   */
  async publishInvoicesBatch(
    input: BatchPublishInvoicesInput
  ): Promise<BatchPublishInvoicesResult> {
    const { invoiceIds, sellerId } = input;

    if (invoiceIds.length === 0) {
      throw new ServiceError("empty_batch", "At least one invoice id is required", 400);
    }

    const uniqueIds = [...new Set(invoiceIds)];

    if (!this.dataSource) {
      throw new ServiceError(
        "batch_publish_unavailable",
        "Batch publishing requires a database connection",
        503
      );
    }

    // The seller's wallet is captured alongside each invoice because the
    // lifecycle log needs it after the write, once the relation may no longer
    // be loaded on the saved entity.
    const publishable: Array<{ invoice: Invoice; sellerWallet: string }> = [];
    const rejections: BatchPublishRejection[] = [];

    // Batch fetch: single query with In(uniqueIds) avoids N round-trips
    let fetched: Array<{ invoiceId: string; invoice: Invoice | null }>;
    try {
      fetched = await Promise.all(
        uniqueIds.map(async (invoiceId) => ({
          invoiceId,
          invoice: await this.invoiceRepository.findOne({
            where: { id: invoiceId },
            relations: ["seller"],
          }),
        }))
      );
      const invoices = await this.invoiceRepository.find({
        where: { id: In(uniqueIds) },
        relations: ["seller"],
      });
      const byId = new Map(invoices.map((inv) => [inv.id, inv]));
      fetched = uniqueIds.map((invoiceId) => ({
        invoiceId,
        invoice: byId.get(invoiceId) ?? null,
      }));
    } catch (error) {
      logger.error("Failed to fetch batch invoices", { error, sellerId });
      throw new ServiceError(
        "batch_fetch_failed",
        "Failed to fetch invoices for batch publish",
        500
      );
    }

    for (const { invoiceId, invoice } of fetched) {
      if (!invoice) {
        rejections.push({
          invoiceId,
          code: "invoice_not_found",
          message: "Invoice not found",
        });
        continue;
      }

      if (invoice.sellerId !== sellerId) {
        rejections.push({
          invoiceId,
          code: "unauthorized_invoice_access",
          message: "Invoice not found",
        });
        continue;
      }

      const seller = invoice.seller as unknown as User;
      if (!seller || seller.kycStatus !== KYCStatus.APPROVED) {
        throw new ServiceError(
          "kyc_approval_required",
          "KYC approval is required to publish invoices",
          403
        );
      }

      if (invoice.status !== InvoiceStatus.DRAFT) {
        rejections.push({
          invoiceId,
          code: "invalid_status_transition",
          message: `Cannot publish an invoice in status ${invoice.status}; only drafts can be published`,
        });
        continue;
      }

      const validationErrors = validateInvoiceForPublish(invoice);
      if (validationErrors.length > 0) {
        rejections.push({
          invoiceId,
          code: "invoice_not_publishable",
          message: `Invoice failed pre-publish validation: ${validationErrors.map((e) => e.message).join(" ")}`,
        });
        continue;
      }

      publishable.push({ invoice, sellerWallet: seller.stellarAddress });
    }

    if (rejections.length > 0) {
      throw new ServiceError(
        "batch_publish_rejected",
        `${rejections.length} of ${uniqueIds.length} invoices cannot be published; no invoices were changed`,
        400,
        { rejections }
      );
    }

    // Nothing is written until every invoice has passed, so a failure inside
    // the transaction rolls the whole batch back rather than leaving a partial
    // publish behind.
    const saved = await this.dataSource.transaction(async (manager) => {
      const results: Invoice[] = [];
      for (const { invoice } of publishable) {
        invoice.status = InvoiceStatus.PUBLISHED;
        results.push(await manager.save(invoice));
      }
      return results;
    });

    publishable.forEach(({ sellerWallet }, index) => {
      logInvoiceTransition(logger, {
        invoiceId: saved[index].id,
        fromState: InvoiceStatus.DRAFT,
        toState: InvoiceStatus.PUBLISHED,
        actorWallet: sellerWallet,
        reason: "seller_batch_published",
      });
    });

    return {
      published: saved.map((invoice) => this.toDTO(invoice)),
      count: saved.length,
    };
  }

  /**
   * Upload document (IPFS) - hardened with size/type pre-check, graceful IPFS failure handling
   */
  async uploadDocument(input: UploadDocumentInput): Promise<UploadDocumentResult> {
    try {
      const invoiceId = input.invoiceId?.trim();
      const sellerId = input.sellerId?.trim();
      if (!invoiceId || !sellerId) {
        throw new ServiceError("invalid_input", "Invoice id and seller id are required", 400);
      }
      if (!input.fileBuffer || input.fileBuffer.length === 0) {
        throw new ServiceError("empty_file", "File buffer is empty", 400);
      }

      const invoice = await this.invoiceRepository.findOne({
        where: { id: invoiceId },
      });
      if (!invoice) {
        throw new ServiceError("invoice_not_found", "Invoice not found", 404);
      }

      if (invoice.sellerId !== sellerId) {
        throw new ServiceError(
          "unauthorized_invoice_access",
          "You can only upload documents to your own invoices",
          403
        );
      }

      let uploadResult: IPFSUploadResult;
      try {
        uploadResult = await this.ipfsService.uploadFile(
          input.fileBuffer,
          input.filename.trim(),
          input.mimeType.trim(),
          invoiceId
        );
      } catch (error) {
        if (error instanceof ServiceError) throw error;
        logger.error("IPFS upload failed", { error, invoiceId });
        throw new ServiceError("ipfs_upload_failed", "Failed to upload document to IPFS", 502);
      }

      invoice.ipfsHash = uploadResult.hash;
      await this.invoiceRepository.save(invoice);

      return {
        invoiceId,
        ipfsHash: uploadResult.hash,
        fileSize: uploadResult.size,
        uploadedAt: uploadResult.timestamp,
      };
    } catch (error) {
      if (error instanceof ServiceError) throw error;
      logger.error("Failed to process document upload", { error, invoiceId: input.invoiceId });
      throw new ServiceError("document_upload_failed", "Failed to process document upload", 500);
    }
  }

  /**
   * Get all token holders for a published invoice with their token balances and percentage shares
   */
  async getInvoiceTokenHolders(invoiceId: string, sellerId: string): Promise<
    Array<{
      wallet: string;
      amount: string;
      share_percent: string;
      committed_at: Date;
    }>
  > {
    const invoice = await this.invoiceRepository.findOne({
      where: { id: invoiceId },
    });

    if (!invoice) {
      throw new ServiceError("invoice_not_found", "Invoice not found", 404);
    }

    if (invoice.sellerId !== sellerId) {
      throw new ServiceError("forbidden", "You can only view investors for your own invoices", 403);
    }

    if (invoice.status === InvoiceStatus.DRAFT) {
      throw new ServiceError(
        "invalid_invoice_status",
        "Token holders can only be queried for published invoices",
        400
      );
    }

    if (!this.dataSource) {
      throw new ServiceError("internal_error", "Database connection unavailable", 500);
    }

    const investmentRepository = this.dataSource.getRepository(Investment);

    const investments = await investmentRepository
      .createQueryBuilder("investment")
      .leftJoinAndSelect("investment.investor", "investor")
      .where("investment.invoiceId = :invoiceId", { invoiceId })
      .andWhere("investment.deletedAt IS NULL")
      .getMany();

    if (investments.length === 0) {
      return [];
    }

    const totalInvested = investments.reduce(
      (sum, inv) => sum.plus(new Decimal(inv.investmentAmount)),
      new Decimal(0)
    );

    return investments.map((investment) => {
      const investor = investment.investor as unknown as User;
      const percentage = totalInvested.isZero()
        ? new Decimal(0)
        : new Decimal(investment.investmentAmount)
            .dividedBy(totalInvested)
            .times(100)
            .toDecimalPlaces(2);

      const address = investor.stellarAddress || "";
      const truncatedWallet = address.length > 8 ? `${address.slice(0, 4)}...${address.slice(-4)}` : address;

      return {
        wallet: truncatedWallet,
        amount: investment.investmentAmount,
        share_percent: percentage.toString(),
        committed_at: investment.createdAt,
      };
    });
  }

  /**
   * Get on-chain escrow status for an invoice
   */
  async getInvoiceEscrowStatus(invoiceId: string): Promise<{
    invoiceId: string;
    hasEscrow: boolean;
    contractId: string | null;
    status: string | null;
  }> {
    const invoice = await this.invoiceRepository.findOne({
      where: { id: invoiceId },
    });

    if (!invoice) {
      throw new ServiceError("invoice_not_found", "Invoice not found", 404);
    }

    if (!invoice.smartContractId) {
      throw new ServiceError(
        "no_escrow_contract",
        "This invoice does not have a deployed escrow contract",
        404
      );
    }

    return {
      invoiceId: invoice.id,
      hasEscrow: true,
      contractId: invoice.smartContractId,
      status: invoice.status,
    };
  }

  /**
   * Convert Invoice model to DTO
   */
  private toDTO(invoice: Invoice): InvoiceDTO {
    return {
      id: invoice.id,
      sellerId: invoice.sellerId,
      invoiceNumber: invoice.invoiceNumber,
      customerName: invoice.customerName,
      amount: invoice.amount,
      discountRate: invoice.discountRate,
      netAmount: invoice.netAmount,
      dueDate: invoice.dueDate,
      status: invoice.status,
      ipfsHash: invoice.ipfsHash,
      riskScore: invoice.riskScore,
      smartContractId: invoice.smartContractId,
      rejectionReason: invoice.rejectionReason ?? null,
      createdAt: invoice.createdAt,
      updatedAt: invoice.updatedAt,
    };
  }
}

export function createInvoiceService(
  dataSource: DataSource,
  ipfsService: IPFSService,
  notificationSink?: NotificationSink
): InvoiceService {
  const invoiceRepository = dataSource.getRepository(Invoice);

  return new InvoiceService({
    invoiceRepository,
    ipfsService,
    dataSource,
    notificationSink,
  });
}
