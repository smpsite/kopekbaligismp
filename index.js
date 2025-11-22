var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// server/index-prod.ts
import fs from "node:fs";
import path from "node:path";
import express2 from "express";

// server/app.ts
import express from "express";
import session from "express-session";
import connectPg from "connect-pg-simple";
import passport2 from "passport";

// server/routes.ts
import { createServer } from "http";

// shared/schema.ts
var schema_exports = {};
__export(schema_exports, {
  insertPurchaseSchema: () => insertPurchaseSchema,
  insertUserSchema: () => insertUserSchema,
  insertVipPackageSchema: () => insertVipPackageSchema,
  purchaseStatuses: () => purchaseStatuses,
  purchases: () => purchases,
  users: () => users,
  vipPackages: () => vipPackages
});
import { sql } from "drizzle-orm";
import { pgTable, text, varchar, timestamp, integer, boolean } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
var users = pgTable("users", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
  minecraftUsername: text("minecraft_username"),
  isAdmin: boolean("is_admin").notNull().default(false)
});
var vipPackages = pgTable("vip_packages", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: text("name").notNull(),
  displayName: text("display_name").notNull(),
  price: integer("price").notNull(),
  features: text("features").array().notNull(),
  icon: text("icon").notNull(),
  color: text("color").notNull()
});
var purchaseStatuses = ["pending", "approved", "rejected"];
var purchases = pgTable("purchases", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").notNull().references(() => users.id),
  packageId: varchar("package_id").notNull().references(() => vipPackages.id),
  status: text("status").notNull().default("pending"),
  paymentMethod: text("payment_method").notNull(),
  paymentProof: text("payment_proof"),
  expiresAt: timestamp("expires_at"),
  createdAt: timestamp("created_at").notNull().default(sql`now()`),
  approvedAt: timestamp("approved_at"),
  approvedBy: varchar("approved_by").references(() => users.id)
});
var insertUserSchema = createInsertSchema(users).omit({
  id: true,
  isAdmin: true
});
var insertVipPackageSchema = createInsertSchema(vipPackages).omit({
  id: true
});
var insertPurchaseSchema = createInsertSchema(purchases).omit({
  id: true,
  createdAt: true,
  approvedAt: true,
  approvedBy: true
});

// server/db.ts
import { drizzle } from "drizzle-orm/neon-serverless";
import ws from "ws";
if (!process.env.DATABASE_URL) {
  throw new Error(
    "DATABASE_URL must be set. Did you forget to provision a database?"
  );
}
var db = drizzle({
  connection: process.env.DATABASE_URL,
  ws,
  schema: schema_exports
});

// server/storage.ts
import { eq, desc } from "drizzle-orm";
var DbStorage = class {
  async getUser(id) {
    const result = await db.select().from(users).where(eq(users.id, id));
    return result[0];
  }
  async getUserByUsername(username) {
    const result = await db.select().from(users).where(eq(users.username, username));
    return result[0];
  }
  async createUser(insertUser) {
    const result = await db.insert(users).values(insertUser).returning();
    return result[0];
  }
  async getVipPackages() {
    return db.select().from(vipPackages);
  }
  async getVipPackage(id) {
    const result = await db.select().from(vipPackages).where(eq(vipPackages.id, id));
    return result[0];
  }
  async createVipPackage(vipPackage) {
    const result = await db.insert(vipPackages).values(vipPackage).returning();
    return result[0];
  }
  async updateVipPackage(id, vipPackage) {
    const result = await db.update(vipPackages).set(vipPackage).where(eq(vipPackages.id, id)).returning();
    return result[0];
  }
  async deleteVipPackage(id) {
    const result = await db.delete(vipPackages).where(eq(vipPackages.id, id)).returning();
    return result.length > 0;
  }
  async getPurchasesByUser(userId) {
    return db.select().from(purchases).where(eq(purchases.userId, userId)).orderBy(desc(purchases.createdAt));
  }
  async getPurchase(id) {
    const result = await db.select().from(purchases).where(eq(purchases.id, id));
    return result[0];
  }
  async createPurchase(purchase) {
    const result = await db.insert(purchases).values(purchase).returning();
    return result[0];
  }
  async updatePurchaseStatus(id, status, approvedBy) {
    const updateData = { status };
    if (status === "approved") {
      updateData.approvedAt = /* @__PURE__ */ new Date();
      if (approvedBy) {
        updateData.approvedBy = approvedBy;
      }
    }
    const result = await db.update(purchases).set(updateData).where(eq(purchases.id, id)).returning();
    return result[0];
  }
  async getPendingPurchases() {
    return db.select().from(purchases).where(eq(purchases.status, "pending")).orderBy(desc(purchases.createdAt));
  }
};
var storage = new DbStorage();

// server/routes.ts
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import bcrypt from "bcrypt";
import { fromError } from "zod-validation-error";
passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const user = await storage.getUserByUsername(username);
      if (!user) {
        return done(null, false, { message: "Kullan\u0131c\u0131 ad\u0131 veya \u015Fifre hatal\u0131" });
      }
      const isValid = await bcrypt.compare(password, user.password);
      if (!isValid) {
        return done(null, false, { message: "Kullan\u0131c\u0131 ad\u0131 veya \u015Fifre hatal\u0131" });
      }
      return done(null, user);
    } catch (error) {
      return done(error);
    }
  })
);
passport.serializeUser((user, done) => {
  done(null, user.id);
});
passport.deserializeUser(async (id, done) => {
  try {
    const user = await storage.getUser(id);
    done(null, user);
  } catch (error) {
    done(error);
  }
});
function requireAuth(req, res, next) {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: "Oturum a\xE7man\u0131z gerekiyor" });
  }
  next();
}
function requireAdmin(req, res, next) {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: "Oturum a\xE7man\u0131z gerekiyor" });
  }
  const user = req.user;
  if (!user.isAdmin) {
    return res.status(403).json({ error: "Bu i\u015Flem i\xE7in yetkiniz yok" });
  }
  next();
}
async function registerRoutes(app2) {
  app2.post("/api/auth/register", async (req, res) => {
    try {
      const validation = insertUserSchema.safeParse(req.body);
      if (!validation.success) {
        return res.status(400).json({ error: fromError(validation.error).toString() });
      }
      const existing = await storage.getUserByUsername(validation.data.username);
      if (existing) {
        return res.status(400).json({ error: "Bu kullan\u0131c\u0131 ad\u0131 zaten kullan\u0131l\u0131yor" });
      }
      const hashedPassword = await bcrypt.hash(validation.data.password, 10);
      const user = await storage.createUser({
        ...validation.data,
        password: hashedPassword
      });
      req.login(user, (err) => {
        if (err) {
          return res.status(500).json({ error: "Giri\u015F yap\u0131lamad\u0131" });
        }
        const { password, ...userWithoutPassword } = user;
        res.json(userWithoutPassword);
      });
    } catch (error) {
      res.status(500).json({ error: "Kay\u0131t s\u0131ras\u0131nda bir hata olu\u015Ftu" });
    }
  });
  app2.post("/api/auth/login", passport.authenticate("local"), (req, res) => {
    const user = req.user;
    const { password, ...userWithoutPassword } = user;
    res.json(userWithoutPassword);
  });
  app2.post("/api/auth/logout", (req, res) => {
    req.logout(() => {
      res.json({ success: true });
    });
  });
  app2.get("/api/auth/me", (req, res) => {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ error: "Oturum a\xE7man\u0131z gerekiyor" });
    }
    const user = req.user;
    const { password, ...userWithoutPassword } = user;
    res.json(userWithoutPassword);
  });
  app2.get("/api/vip-packages", async (req, res) => {
    try {
      const packages = await storage.getVipPackages();
      res.json(packages);
    } catch (error) {
      res.status(500).json({ error: "Paketler y\xFCklenirken hata olu\u015Ftu" });
    }
  });
  app2.post("/api/vip-packages", requireAdmin, async (req, res) => {
    try {
      const validation = insertVipPackageSchema.safeParse(req.body);
      if (!validation.success) {
        return res.status(400).json({ error: fromError(validation.error).toString() });
      }
      const vipPackage = await storage.createVipPackage(validation.data);
      res.json(vipPackage);
    } catch (error) {
      res.status(500).json({ error: "Paket olu\u015Fturulurken hata olu\u015Ftu" });
    }
  });
  app2.patch("/api/vip-packages/:id", requireAdmin, async (req, res) => {
    try {
      const partialSchema = insertVipPackageSchema.partial();
      const validation = partialSchema.safeParse(req.body);
      if (!validation.success) {
        return res.status(400).json({ error: fromError(validation.error).toString() });
      }
      const vipPackage = await storage.updateVipPackage(req.params.id, validation.data);
      if (!vipPackage) {
        return res.status(404).json({ error: "Paket bulunamad\u0131" });
      }
      res.json(vipPackage);
    } catch (error) {
      res.status(500).json({ error: "Paket g\xFCncellenirken hata olu\u015Ftu" });
    }
  });
  app2.delete("/api/vip-packages/:id", requireAdmin, async (req, res) => {
    try {
      const success = await storage.deleteVipPackage(req.params.id);
      if (!success) {
        return res.status(404).json({ error: "Paket bulunamad\u0131" });
      }
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: "Paket silinirken hata olu\u015Ftu" });
    }
  });
  app2.get("/api/purchases", requireAuth, async (req, res) => {
    try {
      const user = req.user;
      const purchases2 = await storage.getPurchasesByUser(user.id);
      res.json(purchases2);
    } catch (error) {
      res.status(500).json({ error: "Sat\u0131n almalar y\xFCklenirken hata olu\u015Ftu" });
    }
  });
  app2.post("/api/purchases", requireAuth, async (req, res) => {
    try {
      const user = req.user;
      const validation = insertPurchaseSchema.safeParse({
        ...req.body,
        userId: user.id,
        status: "pending"
      });
      if (!validation.success) {
        return res.status(400).json({ error: fromError(validation.error).toString() });
      }
      const purchase = await storage.createPurchase({
        ...validation.data,
        status: "pending"
      });
      res.json(purchase);
    } catch (error) {
      res.status(500).json({ error: "Sat\u0131n alma olu\u015Fturulurken hata olu\u015Ftu" });
    }
  });
  app2.get("/api/admin/purchases/pending", requireAdmin, async (req, res) => {
    try {
      const purchases2 = await storage.getPendingPurchases();
      res.json(purchases2);
    } catch (error) {
      res.status(500).json({ error: "Bekleyen sat\u0131n almalar y\xFCklenirken hata olu\u015Ftu" });
    }
  });
  app2.patch("/api/admin/purchases/:id/status", requireAdmin, async (req, res) => {
    try {
      const { status } = req.body;
      if (!purchaseStatuses.includes(status)) {
        return res.status(400).json({ error: "Ge\xE7ersiz durum de\u011Feri" });
      }
      const user = req.user;
      const purchase = await storage.updatePurchaseStatus(
        req.params.id,
        status,
        status === "approved" ? user.id : void 0
      );
      if (!purchase) {
        return res.status(404).json({ error: "Sat\u0131n alma bulunamad\u0131" });
      }
      res.json(purchase);
    } catch (error) {
      res.status(500).json({ error: "Durum g\xFCncellenirken hata olu\u015Ftu" });
    }
  });
  app2.get("/api/server/status", async (req, res) => {
    try {
      const SERVER_IP = "kopekbaligismp.camdvr.org";
      const SERVER_PORT = 25565;
      const response = await fetch(`https://api.minetools.eu/ping/${SERVER_IP}/${SERVER_PORT}`, {
        signal: AbortSignal.timeout(5e3)
      });
      if (!response.ok) {
        return res.json({
          online: false,
          players: 0,
          maxPlayers: 0,
          motd: "Sunucu \xE7evrimd\u0131\u015F\u0131"
        });
      }
      const data = await response.json();
      res.json({
        online: data.status === "success",
        players: data.players?.online || 0,
        maxPlayers: data.players?.max || 0,
        motd: data.description || "K\xF6pekbal\u0131\u011F\u0131 SMP"
      });
    } catch (error) {
      res.json({
        online: false,
        players: 0,
        maxPlayers: 0,
        motd: "Sunucu durumu kontrol edilemiyor"
      });
    }
  });
  const httpServer = createServer(app2);
  return httpServer;
}

// server/app.ts
function log(message, source = "express") {
  const formattedTime = (/* @__PURE__ */ new Date()).toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true
  });
  console.log(`${formattedTime} [${source}] ${message}`);
}
var app = express();
app.use(express.json({
  verify: (req, _res, buf) => {
    req.rawBody = buf;
  }
}));
app.use(express.urlencoded({ extended: false }));
var PgSession = connectPg(session);
app.use(
  session({
    store: new PgSession({
      conString: process.env.DATABASE_URL,
      createTableIfMissing: true
    }),
    secret: process.env.SESSION_SECRET || "kopekbaligi-smp-secret-key-change-in-production",
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 30 * 24 * 60 * 60 * 1e3,
      httpOnly: true,
      secure: process.env.NODE_ENV === "production"
    }
  })
);
app.use(passport2.initialize());
app.use(passport2.session());
app.use((req, res, next) => {
  const start = Date.now();
  const path2 = req.path;
  let capturedJsonResponse = void 0;
  const originalResJson = res.json;
  res.json = function(bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };
  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path2.startsWith("/api")) {
      let logLine = `${req.method} ${path2} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }
      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "\u2026";
      }
      log(logLine);
    }
  });
  next();
});
async function runApp(setup) {
  const server = await registerRoutes(app);
  app.use((err, _req, res, _next) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";
    res.status(status).json({ message });
    throw err;
  });
  await setup(app, server);
  const port = parseInt(process.env.PORT || "5000", 10);
  server.listen({
    port,
    host: "0.0.0.0",
    reusePort: true
  }, () => {
    log(`serving on port ${port}`);
  });
}

// server/index-prod.ts
async function serveStatic(app2, _server) {
  const distPath = path.resolve(import.meta.dirname, "public");
  if (!fs.existsSync(distPath)) {
    throw new Error(
      `Could not find the build directory: ${distPath}, make sure to build the client first`
    );
  }
  app2.use(express2.static(distPath));
  app2.use("*", (_req, res) => {
    res.sendFile(path.resolve(distPath, "index.html"));
  });
}
(async () => {
  await runApp(serveStatic);
})();
export {
  serveStatic
};
