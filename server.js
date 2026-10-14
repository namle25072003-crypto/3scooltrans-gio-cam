require("dotenv").config();
const express = require("express");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const crypto = require("crypto");

const app = express();
const isProd = process.env.NODE_ENV === "production";
const PORT = Number(process.env.PORT || 3000);

if (!process.env.DATABASE_URL) {
  console.error("Missing DATABASE_URL. Set it in your hosting environment.");
  process.exit(1);
}
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  console.error("SESSION_SECRET must be at least 32 characters.");
  process.exit(1);
}
if (!process.env.BOOTSTRAP_ADMIN_USERNAME || !process.env.BOOTSTRAP_ADMIN_PASSWORD) {
  console.error("Set BOOTSTRAP_ADMIN_USERNAME and BOOTSTRAP_ADMIN_PASSWORD in hosting environment.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: isProd ? { rejectUnauthorized: false } : false
});

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "100kb" }));
app.use(express.static(path.join(__dirname, "public"), { index: false }));
app.use(session({
  store: new PgSession({ pool, tableName: "user_sessions", createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: isProd,
    sameSite: "lax",
    maxAge: 8 * 60 * 60 * 1000
  }
}));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Bạn đã thử đăng nhập quá nhiều lần. Vui lòng thử lại sau 15 phút." }
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS app_users (
      id BIGSERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'staff' CHECK (role IN ('admin','staff')),
      permissions JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS vehicles (
      id BIGSERIAL PRIMARY KEY,
      vehicle_name TEXT NOT NULL,
      start_date DATE NOT NULL,
      end_date DATE NOT NULL,
      notes TEXT NOT NULL DEFAULT '',
      created_by BIGINT REFERENCES app_users(id),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CHECK (end_date >= start_date)
    );
  `);
  await pool.query("ALTER TABLE app_users ADD COLUMN IF NOT EXISTS permissions JSONB NOT NULL DEFAULT '{}'::jsonb");
  // Existing staff retain standard vehicle workflows; admins always have full access.
  await pool.query(`UPDATE app_users SET permissions = '{"view_vehicles":true,"add_vehicle":true,"edit_vehicle":true,"delete_vehicle":true,"progress":true,"view_history":true,"edit_history":true,"delete_history":true,"export_csv":true}'::jsonb WHERE role='staff' AND permissions='{}'::jsonb`);
  // Add workflow date fields safely for existing installations; existing vehicle data is preserved.
  await pool.query(`
    ALTER TABLE vehicles ADD COLUMN IF NOT EXISTS document_created_date DATE;
    ALTER TABLE vehicles ADD COLUMN IF NOT EXISTS sent_to_vendor_date DATE;
    ALTER TABLE vehicles ADD COLUMN IF NOT EXISTS accounting_paid_date DATE;
    ALTER TABLE vehicles ADD COLUMN IF NOT EXISTS new_restriction_received_date DATE;
  `);
  // Renewal history is stored separately so past renewals remain available when the current expiry changes.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS vehicle_renewal_history (
      id BIGSERIAL PRIMARY KEY,
      vehicle_id BIGINT NOT NULL REFERENCES vehicles(id) ON DELETE CASCADE,
      renewal_date DATE NOT NULL,
      amount NUMERIC(14,2) NOT NULL DEFAULT 0 CHECK (amount >= 0),
      valid_from DATE NOT NULL,
      valid_until DATE NOT NULL,
      notes TEXT NOT NULL DEFAULT '',
      progress_document_created_date DATE,
      progress_sent_to_vendor_date DATE,
      progress_accounting_paid_date DATE,
      progress_new_restriction_received_date DATE,
      created_by BIGINT REFERENCES app_users(id),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CHECK (valid_until >= valid_from)
    );
    ALTER TABLE vehicle_renewal_history ADD COLUMN IF NOT EXISTS progress_document_created_date DATE;
    ALTER TABLE vehicle_renewal_history ADD COLUMN IF NOT EXISTS progress_sent_to_vendor_date DATE;
    ALTER TABLE vehicle_renewal_history ADD COLUMN IF NOT EXISTS progress_accounting_paid_date DATE;
    ALTER TABLE vehicle_renewal_history ADD COLUMN IF NOT EXISTS progress_new_restriction_received_date DATE;
    CREATE INDEX IF NOT EXISTS idx_vehicle_renewal_history_vehicle_date
      ON vehicle_renewal_history(vehicle_id, renewal_date DESC, id DESC);
  `);
  const { rows } = await pool.query("SELECT id FROM app_users WHERE username=$1", [process.env.BOOTSTRAP_ADMIN_USERNAME]);
  if (!rows.length) {
    const hash = await bcrypt.hash(process.env.BOOTSTRAP_ADMIN_PASSWORD, 12);
    await pool.query(
      "INSERT INTO app_users(username,password_hash,role) VALUES($1,$2,'admin')",
      [process.env.BOOTSTRAP_ADMIN_USERNAME, hash]
    );
    console.log("Bootstrap admin created from environment variables.");
  }
}

function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "Vui lòng đăng nhập." });
  next();
}
function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.session.user) return res.status(401).json({ error: "Vui lòng đăng nhập." });
    if (req.session.user.role === "admin" || req.session.user.permissions?.[permission] === true) return next();
    return res.status(403).json({ error: "Tài khoản của bạn chưa được cấp quyền chức năng này. Vui lòng liên hệ quản trị viên." });
  };
}
function normalizePermissions(input) {
  const keys = ["view_vehicles","add_vehicle","edit_vehicle","delete_vehicle","progress","view_history","edit_history","delete_history","export_csv"];
  const out = {};
  for (const key of keys) out[key] = input && input[key] === true;
  return out;
}
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).json({ error: "Chỉ quản trị viên được thực hiện thao tác này." });
  }
  next();
}
function validDate(s) {
  return typeof s === "string" && /^\d{4}-\d{2}-\d{2}$/.test(s) && !Number.isNaN(Date.parse(s));
}
function cleanVehicle(body) {
  const vehicle_name = String(body.vehicle_name || "").trim();
  const start_date = body.start_date;
  const end_date = body.end_date;
  const notes = String(body.notes || "").trim().slice(0, 1000);
  if (!vehicle_name || vehicle_name.length > 100) throw new Error("Nhập biển số hoặc tên xe (tối đa 100 ký tự).");
  if (!validDate(start_date) || !validDate(end_date)) throw new Error("Ngày bắt đầu/kết thúc không hợp lệ.");
  if (end_date < start_date) throw new Error("Ngày kết thúc không được trước ngày bắt đầu.");
  return { vehicle_name, start_date, end_date, notes };
}

app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("/api/session", async (req, res, next) => {
  try {
    if (!req.session.user) return res.json({ user: null });
    const { rows } = await pool.query("SELECT id,username,role,permissions FROM app_users WHERE id=$1", [req.session.user.id]);
    if (!rows.length) { req.session.destroy(() => {}); return res.json({ user: null }); }
    req.session.user = rows[0];
    res.json({ user: req.session.user });
  } catch (e) { next(e); }
});

app.post("/api/login", loginLimiter, async (req, res, next) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");
    const result = await pool.query(
      "SELECT id,username,password_hash,role,permissions FROM app_users WHERE username=$1",
      [username]
    );
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "Tài khoản hoặc mật khẩu không đúng." });
    }
    req.session.regenerate(err => {
      if (err) return next(err);
      req.session.user = { id: user.id, username: user.username, role: user.role, permissions: user.permissions || {} };
      req.session.save(err2 => {
        if (err2) return next(err2);
        res.json({ user: req.session.user });
      });
    });
  } catch (e) { next(e); }
});

app.post("/api/logout", requireAuth, (req, res, next) => {
  req.session.destroy(err => {
    if (err) return next(err);
    res.clearCookie("connect.sid");
    res.json({ ok: true });
  });
});

app.get("/api/vehicles", requirePermission("view_vehicles"), async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      `SELECT id,vehicle_name,
        to_char(start_date,'YYYY-MM-DD') AS start_date,
        to_char(end_date,'YYYY-MM-DD') AS end_date,
        notes,created_at,updated_at,
        to_char(document_created_date,'YYYY-MM-DD') AS document_created_date,
        to_char(sent_to_vendor_date,'YYYY-MM-DD') AS sent_to_vendor_date,
        to_char(accounting_paid_date,'YYYY-MM-DD') AS accounting_paid_date,
        to_char(new_restriction_received_date,'YYYY-MM-DD') AS new_restriction_received_date
       FROM vehicles ORDER BY end_date ASC, vehicle_name ASC`
    );
    res.json({ vehicles: rows });
  } catch (e) { next(e); }
});

app.post("/api/vehicles", requirePermission("add_vehicle"), async (req, res, next) => {
  try {
    const v = cleanVehicle(req.body);
    const { rows } = await pool.query(
      `INSERT INTO vehicles(vehicle_name,start_date,end_date,notes,created_by)
       VALUES($1,$2,$3,$4,$5)
       RETURNING id,vehicle_name,to_char(start_date,'YYYY-MM-DD') AS start_date,
       to_char(end_date,'YYYY-MM-DD') AS end_date,notes`,
      [v.vehicle_name,v.start_date,v.end_date,v.notes,req.session.user.id]
    );
    res.status(201).json({ vehicle: rows[0] });
  } catch (e) { if (e.message && !e.code) return res.status(400).json({error:e.message}); next(e); }
});

app.put("/api/vehicles/:id", requirePermission("edit_vehicle"), async (req, res, next) => {
  const client = await pool.connect();
  try {
    const v = cleanVehicle(req.body);
    await client.query("BEGIN");
    const currentResult = await client.query(
      `SELECT id, start_date, end_date, document_created_date, sent_to_vendor_date,
              accounting_paid_date, new_restriction_received_date
       FROM vehicles WHERE id=$1 FOR UPDATE`, [req.params.id]
    );
    if (!currentResult.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({error:"Không tìm thấy xe."});
    }
    const old = currentResult.rows[0];
    const oldEndDate = old.end_date instanceof Date ? old.end_date.toISOString().slice(0,10) : String(old.end_date).slice(0,10);
    const expiryChanged = oldEndDate !== v.end_date;
    let amount = null;
    if (expiryChanged) {
      const raw = req.body.renewal_amount;
      amount = Number(raw);
      if (raw === undefined || raw === null || raw === "" || !Number.isFinite(amount) || amount < 0) {
        await client.query("ROLLBACK");
        return res.status(400).json({error:"Bạn đã đổi ngày hết hạn. Vui lòng nhập chi phí gia hạn (có thể nhập 0 nếu miễn phí) để tự lưu lịch sử."});
      }
    }
    const { rows } = await client.query(
      `UPDATE vehicles
       SET vehicle_name=$1, start_date=$2, end_date=$3, notes=$4,
           document_created_date=CASE WHEN end_date IS DISTINCT FROM $3::date THEN NULL ELSE document_created_date END,
           sent_to_vendor_date=CASE WHEN end_date IS DISTINCT FROM $3::date THEN NULL ELSE sent_to_vendor_date END,
           accounting_paid_date=CASE WHEN end_date IS DISTINCT FROM $3::date THEN NULL ELSE accounting_paid_date END,
           new_restriction_received_date=CASE WHEN end_date IS DISTINCT FROM $3::date THEN NULL ELSE new_restriction_received_date END,
           updated_at=NOW()
       WHERE id=$5
       RETURNING id,vehicle_name,to_char(start_date,'YYYY-MM-DD') AS start_date,
       to_char(end_date,'YYYY-MM-DD') AS end_date,notes`,
      [v.vehicle_name,v.start_date,v.end_date,v.notes,req.params.id]
    );
    if (expiryChanged) {
      const receivedDate = old.new_restriction_received_date
        ? (old.new_restriction_received_date instanceof Date ? old.new_restriction_received_date.toISOString().slice(0,10) : String(old.new_restriction_received_date).slice(0,10))
        : new Date().toISOString().slice(0,10);
      await client.query(
        `INSERT INTO vehicle_renewal_history(
           vehicle_id, renewal_date, amount, valid_from, valid_until, notes, created_by,
           progress_document_created_date, progress_sent_to_vendor_date,
           progress_accounting_paid_date, progress_new_restriction_received_date
         ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
        [req.params.id, receivedDate, amount, v.start_date, v.end_date, v.notes,
         req.session.user.id, old.document_created_date, old.sent_to_vendor_date,
         old.accounting_paid_date, old.new_restriction_received_date]
      );
    }
    await client.query("COMMIT");
    res.json({vehicle:rows[0], history_saved:expiryChanged});
  } catch (e) {
    try { await client.query("ROLLBACK"); } catch {}
    if (e.message && !e.code) return res.status(400).json({error:e.message});
    next(e);
  } finally { client.release(); }
});

app.put("/api/vehicles/:id/progress", requirePermission("progress"), async (req, res, next) => {
  try {
    const fields = ["document_created_date", "sent_to_vendor_date", "accounting_paid_date", "new_restriction_received_date"];
    const values = fields.map(field => {
      const value = req.body[field];
      if (value === null || value === undefined || value === "") return null;
      if (!validDate(value)) throw new Error("Ngày trong tiến độ hồ sơ không hợp lệ.");
      return value;
    });
    const { rows } = await pool.query(
      `UPDATE vehicles SET document_created_date=$1,sent_to_vendor_date=$2,accounting_paid_date=$3,new_restriction_received_date=$4,updated_at=NOW()
       WHERE id=$5
       RETURNING id,vehicle_name,to_char(document_created_date,'YYYY-MM-DD') AS document_created_date,
       to_char(sent_to_vendor_date,'YYYY-MM-DD') AS sent_to_vendor_date,
       to_char(accounting_paid_date,'YYYY-MM-DD') AS accounting_paid_date,
       to_char(new_restriction_received_date,'YYYY-MM-DD') AS new_restriction_received_date`,
      [...values, req.params.id]
    );
    if (!rows.length) return res.status(404).json({error:"Không tìm thấy xe."});
    res.json({vehicle:rows[0]});
  } catch (e) { if (e.message && !e.code) return res.status(400).json({error:e.message}); next(e); }
});

app.get("/api/vehicles/:id/renewal-history", requirePermission("view_history"), async (req, res, next) => {
  try {
    const vehicle = await pool.query("SELECT id, vehicle_name FROM vehicles WHERE id=$1", [req.params.id]);
    if (!vehicle.rowCount) return res.status(404).json({error:"Không tìm thấy xe."});
    const { rows } = await pool.query(
      `SELECT id, to_char(renewal_date,'YYYY-MM-DD') AS renewal_date,
       amount::text AS amount, to_char(valid_from,'YYYY-MM-DD') AS valid_from,
       to_char(valid_until,'YYYY-MM-DD') AS valid_until, notes,
       to_char(progress_document_created_date,'YYYY-MM-DD') AS progress_document_created_date,
       to_char(progress_sent_to_vendor_date,'YYYY-MM-DD') AS progress_sent_to_vendor_date,
       to_char(progress_accounting_paid_date,'YYYY-MM-DD') AS progress_accounting_paid_date,
       to_char(progress_new_restriction_received_date,'YYYY-MM-DD') AS progress_new_restriction_received_date
       FROM vehicle_renewal_history WHERE vehicle_id=$1
       ORDER BY renewal_date DESC, id DESC`, [req.params.id]
    );
    res.json({vehicle:vehicle.rows[0], history:rows, renewal_count:rows.length});
  } catch (e) { next(e); }
});

app.put("/api/vehicles/:id/renewal-history/:historyId", requirePermission("edit_history"), async (req, res, next) => {
  try {
    const vehicleId = req.params.id;
    const historyId = req.params.historyId;
    const renewal_date = req.body.renewal_date;
    const valid_from = req.body.valid_from;
    const valid_until = req.body.valid_until;
    const amountRaw = req.body.amount;
    const amount = Number(amountRaw);
    const notes = String(req.body.notes || "").trim().slice(0, 1000);
    const dateFields = [
      req.body.progress_document_created_date,
      req.body.progress_sent_to_vendor_date,
      req.body.progress_accounting_paid_date,
      req.body.progress_new_restriction_received_date
    ];
    if (!validDate(renewal_date) || !validDate(valid_from) || !validDate(valid_until)) {
      return res.status(400).json({error:"Vui lòng nhập đủ ngày gia hạn, ngày bắt đầu và ngày hết hạn."});
    }
    if (valid_until < valid_from) return res.status(400).json({error:"Thời hạn đến ngày không được trước ngày bắt đầu."});
    if (amountRaw === undefined || amountRaw === null || amountRaw === "" || !Number.isFinite(amount) || amount < 0) {
      return res.status(400).json({error:"Số tiền không hợp lệ."});
    }
    const progress = dateFields.map(value => {
      if (value === null || value === undefined || value === "") return null;
      if (!validDate(value)) throw new Error("Ngày trong tiến độ hồ sơ không hợp lệ.");
      return value;
    });
    const { rows } = await pool.query(
      `UPDATE vehicle_renewal_history SET renewal_date=$1, amount=$2, valid_from=$3, valid_until=$4, notes=$5,
       progress_document_created_date=$6, progress_sent_to_vendor_date=$7,
       progress_accounting_paid_date=$8, progress_new_restriction_received_date=$9
       WHERE id=$10 AND vehicle_id=$11
       RETURNING id, to_char(renewal_date,'YYYY-MM-DD') AS renewal_date, amount::text AS amount,
       to_char(valid_from,'YYYY-MM-DD') AS valid_from, to_char(valid_until,'YYYY-MM-DD') AS valid_until, notes,
       to_char(progress_document_created_date,'YYYY-MM-DD') AS progress_document_created_date,
       to_char(progress_sent_to_vendor_date,'YYYY-MM-DD') AS progress_sent_to_vendor_date,
       to_char(progress_accounting_paid_date,'YYYY-MM-DD') AS progress_accounting_paid_date,
       to_char(progress_new_restriction_received_date,'YYYY-MM-DD') AS progress_new_restriction_received_date`,
      [renewal_date, amount, valid_from, valid_until, notes, ...progress, historyId, vehicleId]
    );
    if (!rows.length) return res.status(404).json({error:"Không tìm thấy lần gia hạn này."});
    res.json({record:rows[0]});
  } catch (e) { if (e.message && !e.code) return res.status(400).json({error:e.message}); next(e); }
});

app.delete("/api/vehicles/:id/renewal-history/:historyId", requirePermission("delete_history"), async (req, res, next) => {
  try {
    const result = await pool.query(
      "DELETE FROM vehicle_renewal_history WHERE id=$1 AND vehicle_id=$2",
      [req.params.historyId, req.params.id]
    );
    if (!result.rowCount) return res.status(404).json({error:"Không tìm thấy lần gia hạn này."});
    res.json({ok:true});
  } catch (e) { next(e); }
});

app.post("/api/vehicles/:id/renewal-history", requirePermission("edit_history"), async (req, res, next) => {
  try {
    const vehicleId = req.params.id;
    const vehicle = await pool.query(
      `SELECT id, document_created_date, sent_to_vendor_date, accounting_paid_date, new_restriction_received_date
       FROM vehicles WHERE id=$1`, [vehicleId]
    );
    if (!vehicle.rowCount) return res.status(404).json({error:"Không tìm thấy xe."});
    const renewal_date = req.body.renewal_date;
    const valid_from = req.body.valid_from;
    const valid_until = req.body.valid_until;
    const amountRaw = req.body.amount;
    const amount = Number(amountRaw);
    const notes = String(req.body.notes || "").trim().slice(0, 1000);
    if (!validDate(renewal_date) || !validDate(valid_from) || !validDate(valid_until)) {
      return res.status(400).json({error:"Vui lòng nhập đủ ngày gia hạn, ngày bắt đầu và ngày hết hạn."});
    }
    if (valid_until < valid_from) return res.status(400).json({error:"Thời hạn đến ngày không được trước ngày bắt đầu."});
    if (amountRaw === undefined || amountRaw === null || amountRaw === "" || !Number.isFinite(amount) || amount < 0) {
      return res.status(400).json({error:"Số tiền không hợp lệ."});
    }
    const { rows } = await pool.query(
      `INSERT INTO vehicle_renewal_history(
         vehicle_id,renewal_date,amount,valid_from,valid_until,notes,created_by,
         progress_document_created_date,progress_sent_to_vendor_date,
         progress_accounting_paid_date,progress_new_restriction_received_date
       ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
       RETURNING id, to_char(renewal_date,'YYYY-MM-DD') AS renewal_date,
       amount::text AS amount, to_char(valid_from,'YYYY-MM-DD') AS valid_from,
       to_char(valid_until,'YYYY-MM-DD') AS valid_until, notes,
       to_char(progress_document_created_date,'YYYY-MM-DD') AS progress_document_created_date,
       to_char(progress_sent_to_vendor_date,'YYYY-MM-DD') AS progress_sent_to_vendor_date,
       to_char(progress_accounting_paid_date,'YYYY-MM-DD') AS progress_accounting_paid_date,
       to_char(progress_new_restriction_received_date,'YYYY-MM-DD') AS progress_new_restriction_received_date`,
      [vehicleId, renewal_date, amount, valid_from, valid_until, notes, req.session.user.id,
       vehicle.rows[0].document_created_date, vehicle.rows[0].sent_to_vendor_date,
       vehicle.rows[0].accounting_paid_date, vehicle.rows[0].new_restriction_received_date]
    );
    res.status(201).json({record:rows[0]});
  } catch (e) { next(e); }
});

app.delete("/api/vehicles/:id", requirePermission("delete_vehicle"), async (req, res, next) => {
  try {
    const result = await pool.query("DELETE FROM vehicles WHERE id=$1", [req.params.id]);
    if (!result.rowCount) return res.status(404).json({error:"Không tìm thấy xe."});
    res.json({ok:true});
  } catch (e) { next(e); }
});

// User management is restricted to admins. Passwords are never returned by the API.
app.get("/api/users", requireAdmin, async (req, res, next) => {
  try {
    const { rows } = await pool.query("SELECT id,username,role,permissions,created_at FROM app_users ORDER BY id");
    res.json({users:rows});
  } catch (e) { next(e); }
});
app.post("/api/users", requireAdmin, async (req, res, next) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");
    const role = req.body.role === "admin" ? "admin" : "staff";
    const permissions = role === "admin" ? {} : normalizePermissions(req.body.permissions);
    if (!/^[a-zA-Z0-9._-]{3,40}$/.test(username)) return res.status(400).json({error:"Tên đăng nhập 3–40 ký tự, chỉ gồm chữ, số, dấu chấm, gạch ngang hoặc gạch dưới."});
    if (!password.length) return res.status(400).json({error:"Vui lòng nhập mật khẩu."});
    const hash = await bcrypt.hash(password, 12);
    const { rows } = await pool.query(
      "INSERT INTO app_users(username,password_hash,role,permissions) VALUES($1,$2,$3,$4) RETURNING id,username,role,permissions,created_at",
      [username,hash,role,JSON.stringify(permissions)]
    );
    res.status(201).json({user:rows[0]});
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({error:"Tên đăng nhập đã tồn tại."});
    next(e);
  }
});
app.put("/api/users/:id/password", requireAdmin, async (req, res, next) => {
  try {
    const password = String(req.body.password ?? "");
    if (!password.length) return res.status(400).json({error:"Vui lòng nhập mật khẩu mới."});
    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query("UPDATE app_users SET password_hash=$1 WHERE id=$2 RETURNING id,username,role", [hash, req.params.id]);
    if (!result.rows.length) return res.status(404).json({error:"Không tìm thấy tài khoản."});
    res.json({ok:true, user:result.rows[0]});
  } catch (e) { next(e); }
});
app.put("/api/users/:id/permissions", requireAdmin, async (req, res, next) => {
  try {
    if (String(req.session.user.id) === String(req.params.id)) return res.status(400).json({error:"Không thể thay đổi quyền của tài khoản quản trị đang sử dụng."});
    const permissions = normalizePermissions(req.body.permissions);
    const { rows } = await pool.query(
      "UPDATE app_users SET permissions=$1::jsonb WHERE id=$2 AND role='staff' RETURNING id,username,role,permissions,created_at",
      [JSON.stringify(permissions), req.params.id]
    );
    if (!rows.length) return res.status(404).json({error:"Không tìm thấy tài khoản nhân viên."});
    res.json({user:rows[0]});
  } catch (e) { next(e); }
});
app.delete("/api/users/:id", requireAdmin, async (req, res, next) => {
  try {
    if (String(req.session.user.id) === String(req.params.id)) return res.status(400).json({error:"Không thể tự xóa tài khoản đang đăng nhập."});
    const result = await pool.query("DELETE FROM app_users WHERE id=$1", [req.params.id]);
    if (!result.rowCount) return res.status(404).json({error:"Không tìm thấy tài khoản."});
    res.json({ok:true});
  } catch (e) { next(e); }
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({error:"Có lỗi máy chủ. Vui lòng thử lại hoặc liên hệ quản trị viên."});
});

initDb().then(() => {
  app.listen(PORT, () => console.log(`3SCooltrans app listening on port ${PORT}`));
}).catch(err => {
  console.error("Database initialization failed:", err);
  process.exit(1);
});
