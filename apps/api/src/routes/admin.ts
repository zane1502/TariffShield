import { Router, type Request, type Response } from "express";
import { z } from "zod";
import { pool } from "../db.js";
import { authMiddleware, requireRole, privacyReacceptanceGate, type AuthedRequest } from "../auth.js";
import { platformKeypair, oracleKeypair } from "../stellar.js";

export const adminRouter = Router();
adminRouter.use(authMiddleware);
adminRouter.use(privacyReacceptanceGate);

adminRouter.get("/oracle-alerts", async (req: Request, res: Response) => {
  const user = (req as AuthedRequest).user;
  if (user.role !== "surety_admin") {
    res.status(403).json({ error: "surety admin only" });
    return;
  }

  const limit = Math.min(parseInt(req.query.limit as string) || 50, 100);
  const offset = parseInt(req.query.offset as string) || 0;

  const r = await pool.query(
    "SELECT * FROM oracle_alerts ORDER BY alerted_at DESC LIMIT $1 OFFSET $2",
    [limit, offset]
  );
  
  const countR = await pool.query("SELECT COUNT(*) FROM oracle_alerts");
  const total = parseInt(countR.rows[0]?.count || "0");

  res.json({
    alerts: r.rows,
    total,
    limit,
    offset,
  });
});

adminRouter.patch("/oracle-alerts/:id/acknowledge", async (req: Request, res: Response) => {
  const user = (req as AuthedRequest).user;
  if (user.role !== "surety_admin") {
    res.status(403).json({ error: "surety admin only" });
    return;
  }

  const alertId = req.params.id;
  const r = await pool.query(
    "UPDATE oracle_alerts SET acknowledged_at = now() WHERE id = $1 RETURNING *",
    [alertId]
  );

  if (r.rowCount === 0) {
    res.status(404).json({ error: "alert not found" });
    return;
  }

  res.json({ alert: r.rows[0] });
});

// #339 — GET /admin/roles — operational visibility into current role addresses
adminRouter.get("/roles", requireRole("surety_admin"), (_req: Request, res: Response) => {
  res.json({
    generalAdmin: platformKeypair.publicKey(),
    oracleAdmin: oracleKeypair.publicKey(),
    rolesAreDistinct: platformKeypair.publicKey() !== oracleKeypair.publicKey(),
  });
});

// #341 — GET /admin/oracle-feed — oracle price feeds with importer_id/from/to filters and pagination
adminRouter.get(
  "/oracle-feed",
  requireRole("surety_admin"),
  async (req: Request, res: Response) => {
    const importerId = req.query.importer_id as string | undefined;
    const from = req.query.from as string | undefined;
    const to = req.query.to as string | undefined;
    const limit = Math.min(parseInt(req.query.limit as string) || 50, 100);
    const offset = parseInt(req.query.offset as string) || 0;

    // Build WHERE clause dynamically with parameterized values
    let whereSql = "";
    let countSql = "";
    const values: unknown[] = [];
    let paramCount = 0;

    if (importerId) {
      whereSql += `oi.importer_id = $${++paramCount}, `;
      countSql += `oi.importer_id = $${++paramCount}, `;
      values.push(importerId);
    }

    if (from) {
      whereSql += `oracle_price_feed.recorded_at >= $${++paramCount}, `;
      countSql += `oracle_price_feed.recorded_at >= $${++paramCount}, `;
      values.push(new Date(from));
    }

    if (to) {
      whereSql += `oracle_price_feed.recorded_at <= $${++paramCount}, `;
      countSql += `oracle_price_feed.recorded_at <= $${++paramCount}, `;
      values.push(new Date(to));
    }

    // Remove trailing comma and space
    if (paramCount > 0) {
      whereSql = whereSql.slice(0, -2);
      countSql = countSql.slice(0, -2);
    }

    const fullWhereSql = whereSql ? `WHERE ${whereSql}` : "";
    const fullCountSql = countSql ? `WHERE ${countSql}` : "";

    // Count total matching rows
    const countResult = await pool.query(
      `SELECT COUNT(*) FROM oracle_price_feed oi ${fullCountSql}`,
      values.length > 0 ? values.slice(0, paramCount) : undefined
    );
    const total = parseInt(countResult.rows[0]?.count || "0");

    // Fetch paginated rows
    const query = `SELECT oi.*, u.email AS importer_email FROM oracle_price_feed oi LEFT JOIN importers i ON i.id = oi.importer_id LEFT JOIN users u ON u.id = i.user_id ${fullWhereSql} ORDER BY oi.recorded_at DESC LIMIT $${paramCount + 1} OFFSET $${paramCount + 2}`;
    const pageValues = [...values, limit, offset];

    const result = await pool.query(query, pageValues);

    res.json({
      data: result.rows,
      total,
      limit,
      offset,
      page: Math.ceil(total / limit) || 1,
    });
  }
);

// #322 — POST /admin/privacy-policy/publish — publish a new privacy policy version
adminRouter.post(
  "/privacy-policy/publish",
  requireRole("surety_admin"),
  async (req: Request, res: Response) => {
    const user = (req as AuthedRequest).user;
    const parse = z.object({
      versionId: z.string().min(1),
      effectiveDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
      changeSummary: z.string().min(10),
      policyText: z.string().optional(),
      requiresReacceptance: z.boolean().default(false),
    }).safeParse(req.body);

    if (!parse.success) {
      res.status(400).json({ error: "invalid input", details: parse.error.issues });
      return;
    }
    const { versionId, effectiveDate, changeSummary, policyText, requiresReacceptance } = parse.data;

    const result = await pool.query(
      `INSERT INTO privacy_policy_versions
         (version_id, effective_date, policy_text, change_summary, requires_reacceptance, published_by)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, version_id, effective_date, requires_reacceptance, published_at`,
      [versionId, effectiveDate, policyText ?? null, changeSummary, requiresReacceptance, user.id],
    );

    if (requiresReacceptance) {
      // Flag all active users so their next request returns 403 with reason
      await pool.query(
        `UPDATE users SET privacy_reacceptance_required = TRUE
         WHERE role IN ('importer', 'surety_admin')`,
      );
    }

    res.status(201).json({ version: result.rows[0] });
  },
);

// #342 — GET /admin/oracle-feed/export.csv — export oracle price feeds as CSV (RFC 4180)
adminRouter.get(
  "/oracle-feed/export.csv",
  requireRole("surety_admin"),
  async (req: Request, res: Response) => {
    const importerId = req.query.importer_id as string | undefined;
    const from = req.query.from as string | undefined;
    const to = req.query.to as string | undefined;

    // Build WHERE clause dynamically with parameterized values
    let whereSql = "";
    const values: unknown[] = [];
    let paramCount = 0;

    if (importerId) {
      whereSql += `oi.importer_id = $${++paramCount}, `;
      values.push(importerId);
    }

    if (from) {
      whereSql += `oracle_price_feed.recorded_at >= $${++paramCount}, `;
      values.push(new Date(from));
    }

    if (to) {
      whereSql += `oracle_price_feed.recorded_at <= $${++paramCount}, `;
      values.push(new Date(to));
    }

    if (paramCount > 0) {
      whereSql = whereSql.slice(0, -2);
    }

    const fullWhereSql = whereSql ? `WHERE ${whereSql}` : "";

    // Fetch all matching rows
    const query = `SELECT oi.set_by, oi.value, oi.recorded_at FROM oracle_price_feed oi ${fullWhereSql} ORDER BY oi.recorded_at DESC`;
    const results = await pool.query(query, values);

    // Build CSV content per RFC 4180
    function escapeCsvField(field: string): string {
      if (field.includes(",") || field.includes('"') || field.includes("\n")) {
        return `"${field.replace(/"/, '""')}"`;
      }
      return field;
    }

    const header = "set_by,value,recorded_at";
    const rows: string[] = [header];

    for (const row of results.rows) {
      const setBy = escapeCsvField(row.set_by ?? "");
      const value = escapeCsvField(row.value?.toString() ?? "");
      const recordedAt = escapeCsvField(row.recorded_at?.toISOString() ?? "");
      rows.push(`${setBy},${value},${recordedAt}`);
    }

    const csvContent = rows.join("\n");
    res.header("Content-Type", "text/csv");
    res.attachment("oracle-price-feed.csv");
    res.send(csvContent);
  }
);
