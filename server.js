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
  // Add workflow date fields safely for existing installations; existing vehicle data is preserved.
  await pool.query(`
    ALTER TABLE vehicles ADD COLUMN IF NOT EXISTS document_created_date DATE;
    ALTER TABLE vehicles ADD COLUMN IF NOT EXISTS sent_to_vendor_date DATE;
    ALTER TABLE vehicles ADD COLUMN IF NOT EXISTS accounting_paid_date DATE;
    ALTER TABLE vehicles ADD COLUMN IF NOT EXISTS new_restriction_received_date DATE;
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
app.get("/api/session", (req, res) => res.json({ user: req.session.user || null }));

app.post("/api/login", loginLimiter, async (req, res, next) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");
    const result = await pool.query(
      "SELECT id,username,password_hash,role FROM app_users WHERE username=$1",
      [username]
    );
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "Tài khoản hoặc mật khẩu không đúng." });
    }
    req.session.regenerate(err => {
      if (err) return next(err);
      req.session.user = { id: user.id, username: user.username, role: user.role };
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

app.get("/api/vehicles", requireAuth, async (req, res, next) => {
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

app.post("/api/vehicles", requireAuth, async (req, res, next) => {
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

app.put("/api/vehicles/:id", requireAuth, async (req, res, next) => {
  try {
    const v = cleanVehicle(req.body);
    const { rows } = await pool.query(
      `UPDATE vehicles SET vehicle_name=$1,start_date=$2,end_date=$3,notes=$4,updated_at=NOW()
       WHERE id=$5
       RETURNING id,vehicle_name,to_char(start_date,'YYYY-MM-DD') AS start_date,
       to_char(end_date,'YYYY-MM-DD') AS end_date,notes`,
      [v.vehicle_name,v.start_date,v.end_date,v.notes,req.params.id]
    );
    if (!rows.length) return res.status(404).json({error:"Không tìm thấy xe."});
    res.json({vehicle:rows[0]});
  } catch (e) { if (e.message && !e.code) return res.status(400).json({error:e.message}); next(e); }
});

app.put("/api/vehicles/:id/progress", requireAuth, async (req, res, next) => {
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

app.delete("/api/vehicles/:id", requireAuth, async (req, res, next) => {
  try {
    const result = await pool.query("DELETE FROM vehicles WHERE id=$1", [req.params.id]);
    if (!result.rowCount) return res.status(404).json({error:"Không tìm thấy xe."});
    res.json({ok:true});
  } catch (e) { next(e); }
});

// User management is restricted to admins. Passwords are never returned by the API.
app.get("/api/users", requireAdmin, async (req, res, next) => {
  try {
    const { rows } = await pool.query("SELECT id,username,role,created_at FROM app_users ORDER BY id");
    res.json({users:rows});
  } catch (e) { next(e); }
});
app.post("/api/users", requireAdmin, async (req, res, next) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");
    const role = req.body.role === "admin" ? "admin" : "staff";
    if (!/^[a-zA-Z0-9._-]{3,40}$/.test(username)) return res.status(400).json({error:"Tên đăng nhập 3–40 ký tự, chỉ gồm chữ, số, dấu chấm, gạch ngang hoặc gạch dưới."});
    if (password.length < 12) return res.status(400).json({error:"Mật khẩu phải có ít nhất 12 ký tự."});
    const hash = await bcrypt.hash(password, 12);
    const { rows } = await pool.query(
      "INSERT INTO app_users(username,password_hash,role) VALUES($1,$2,$3) RETURNING id,username,role,created_at",
      [username,hash,role]
    );
    res.status(201).json({user:rows[0]});
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({error:"Tên đăng nhập đã tồn tại."});
    next(e);
  }
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
