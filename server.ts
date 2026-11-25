import 'dotenv/config';
import express from 'express';
import type { Request, Response, NextFunction } from 'express';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

interface StoredUser {
  id: string;
  name: string;
  gamerTag: string;
  email: string;
  passwordSalt: string;
  passwordHash: string;
  createdAt: string;
}

interface StoredOrder {
  id: string;
  userId: string;
  userName: string;
  userEmail: string;
  bannerId: string;
  bannerTitle: string;
  channelTitle: string;
  tagline: string;
  platform: string;
  accentColor: string;
  addonIds: string[];
  notes: string;
  totalUsd: number;
  status: string;
  createdAt: string;
}

interface StoreData {
  users: StoredUser[];
  orders: StoredOrder[];
}

interface AuthenticatedRequest extends Request {
  authUser?: {
    id: string;
    email: string;
    name: string;
    gamerTag: string;
  };
}

const PORT = Number(process.env.PORT) || 3000;
const PRIMARY_DATA_DIR = path.resolve(process.cwd(), 'data');
const FALLBACK_DATA_DIR = path.resolve(os.tmpdir(), 'adeel-banners-data');

function resolveStoreLocation(): { dir: string; file: string } {
  for (const dir of [PRIMARY_DATA_DIR, FALLBACK_DATA_DIR]) {
    try {
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      const file = path.resolve(dir, 'store.json');
      if (!file.startsWith(dir + path.sep)) {
        continue;
      }
      if (!fs.existsSync(file)) {
        fs.writeFileSync(file, JSON.stringify({ users: [], orders: [] }, null, 2), 'utf-8');
      }
      return { dir, file };
    } catch {
      // Try next writable location
    }
  }
  return { dir: FALLBACK_DATA_DIR, file: path.resolve(FALLBACK_DATA_DIR, 'store.json') };
}

const STORE_LOC = resolveStoreLocation();
const DATA_DIR = STORE_LOC.dir;
const STORE_PATH = STORE_LOC.file;

if (!STORE_PATH.startsWith(DATA_DIR + path.sep)) {
  throw new Error('Invalid store path configuration');
}

let memoryStore: StoreData = { users: [], orders: [] };

const SESSION_SECRET =
  process.env.SESSION_SECRET && process.env.SESSION_SECRET.length >= 16
    ? process.env.SESSION_SECRET
    : crypto.randomBytes(32).toString('hex');

const BANNER_PRICING: Record<string, { title: string; priceUsd: number }> = {
  'tactical-vanguard': { title: 'Tactical Vanguard FPS Header', priceUsd: 25 },
  'apex-dropzone': { title: 'Alpine Dropzone Battle Royale', priceUsd: 35 },
  'gt3-night-circuit': { title: 'Night Circuit GT3 Motorsport', priceUsd: 30 },
  'obsidian-citadel': { title: 'Obsidian Citadel RPG Crest', priceUsd: 40 },
};

const PLATFORM_OPTIONS = new Set([
  'YouTube (2560x1440)',
  'Twitch (1200x480)',
  'Kick & Discord Kit',
  'Full Streamer Bundle',
]);

const ADDON_PRICING: Record<string, number> = {
  'matching-avatar': 15,
  'source-psd': 20,
  'express-12h': 15,
};

function ensureStore(): StoreData {
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    if (!fs.existsSync(STORE_PATH)) {
      fs.writeFileSync(STORE_PATH, JSON.stringify(memoryStore, null, 2), 'utf-8');
      return memoryStore;
    }
    const raw = fs.readFileSync(STORE_PATH, 'utf-8');
    const parsed = JSON.parse(raw) as Partial<StoreData>;
    memoryStore = {
      users: Array.isArray(parsed.users) ? parsed.users : [],
      orders: Array.isArray(parsed.orders) ? parsed.orders : [],
    };
    return memoryStore;
  } catch {
    return memoryStore;
  }
}

function saveStore(data: StoreData): void {
  memoryStore = data;
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    fs.writeFileSync(STORE_PATH, JSON.stringify(data, null, 2), 'utf-8');
  } catch {
    // Retain in-memory store if disk write is unavailable
  }
}

function hashPassword(password: string, salt: string): string {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

function verifyPassword(password: string, salt: string, expectedHash: string): boolean {
  const actual = Buffer.from(hashPassword(password, salt), 'hex');
  const expected = Buffer.from(expectedHash, 'hex');
  if (actual.length !== expected.length) return false;
  return crypto.timingSafeEqual(actual, expected);
}

function signToken(user: StoredUser): string {
  const payload = {
    sub: user.id,
    email: user.email,
    name: user.name,
    gamerTag: user.gamerTag,
    exp: Date.now() + 7 * 24 * 60 * 60 * 1000,
  };
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto
    .createHmac('sha256', SESSION_SECRET)
    .update(encoded)
    .digest('base64url');
  return `${encoded}.${sig}`;
}

function verifyToken(token: string): AuthenticatedRequest['authUser'] | null {
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [encoded, sig] = parts;
  const expectedSig = crypto
    .createHmac('sha256', SESSION_SECRET)
    .update(encoded)
    .digest('base64url');

  const sigBuf = Buffer.from(sig);
  const expBuf = Buffer.from(expectedSig);
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    return null;
  }

  try {
    const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf-8')) as {
      sub?: string;
      email?: string;
      name?: string;
      gamerTag?: string;
      exp?: number;
    };
    if (!payload.sub || !payload.email || !payload.exp || Date.now() > payload.exp) {
      return null;
    }
    return {
      id: payload.sub,
      email: payload.email,
      name: payload.name || 'Customer',
      gamerTag: payload.gamerTag || '',
    };
  } catch {
    return null;
  }
}

function requireAuth(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): void {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Please sign in to access your customer account.' });
    return;
  }
  const token = header.slice(7).trim();
  const decoded = verifyToken(token);
  if (!decoded) {
    res.status(401).json({ error: 'Session expired. Please sign in again.' });
    return;
  }
  const store = ensureStore();
  const user = store.users.find((u) => u.id === decoded.id);
  if (!user) {
    res.status(401).json({ error: 'Account not found. Please sign in again.' });
    return;
  }
  req.authUser = {
    id: user.id,
    email: user.email,
    name: user.name,
    gamerTag: user.gamerTag,
  };
  next();
}

const app = express();
app.use(express.json({ limit: '64kb' }));

app.get('/api/health', (_req, res) => {
  res.json({ ok: true });
});

app.post('/api/auth/register', (req, res) => {
  const body = req.body as Record<string, unknown>;
  const name = typeof body.name === 'string' ? body.name.trim() : '';
  const gamerTag = typeof body.gamerTag === 'string' ? body.gamerTag.trim() : '';
  const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
  const password = typeof body.password === 'string' ? body.password : '';

  if (name.length < 2 || name.length > 80) {
    res.status(400).json({ error: 'Please enter your full name (2–80 characters).' });
    return;
  }
  if (gamerTag.length > 40) {
    res.status(400).json({ error: 'Gamer tag must be under 40 characters.' });
    return;
  }
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email) || email.length > 120) {
    res.status(400).json({ error: 'Please enter a valid email address.' });
    return;
  }
  if (password.length < 6 || password.length > 100) {
    res.status(400).json({ error: 'Password must be between 6 and 100 characters.' });
    return;
  }

  const store = ensureStore();
  if (store.users.some((u) => u.email === email)) {
    res.status(409).json({ error: 'An account with this email already exists. Please sign in.' });
    return;
  }

  const salt = crypto.randomBytes(16).toString('hex');
  const newUser: StoredUser = {
    id: `usr_${crypto.randomUUID().slice(0, 8)}`,
    name,
    gamerTag: gamerTag || name,
    email,
    passwordSalt: salt,
    passwordHash: hashPassword(password, salt),
    createdAt: new Date().toISOString(),
  };

  store.users.push(newUser);
  saveStore(store);

  const token = signToken(newUser);
  res.status(201).json({
    token,
    user: {
      id: newUser.id,
      name: newUser.name,
      gamerTag: newUser.gamerTag,
      email: newUser.email,
    },
  });
});

app.post('/api/auth/login', (req, res) => {
  const body = req.body as Record<string, unknown>;
  const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
  const password = typeof body.password === 'string' ? body.password : '';

  if (!email || !password) {
    res.status(400).json({ error: 'Please enter both email and password.' });
    return;
  }

  const store = ensureStore();
  const user = store.users.find((u) => u.email === email);
  if (!user || !verifyPassword(password, user.passwordSalt, user.passwordHash)) {
    res.status(401).json({ error: 'Invalid email or password.' });
    return;
  }

  const token = signToken(user);
  res.json({
    token,
    user: {
      id: user.id,
      name: user.name,
      gamerTag: user.gamerTag,
      email: user.email,
    },
  });
});

app.get('/api/auth/me', requireAuth, (req: AuthenticatedRequest, res) => {
  res.json({ user: req.authUser });
});

app.get('/api/orders', requireAuth, (req: AuthenticatedRequest, res) => {
  const store = ensureStore();
  const orders = store.orders
    .filter((o) => o.userId === req.authUser!.id)
    .sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
  res.json({ orders });
});

app.post('/api/orders', requireAuth, (req: AuthenticatedRequest, res) => {
  const body = req.body as Record<string, unknown>;
  const bannerId = typeof body.bannerId === 'string' ? body.bannerId.trim() : '';
  const channelTitle =
    typeof body.channelTitle === 'string' ? body.channelTitle.trim() : '';
  const tagline = typeof body.tagline === 'string' ? body.tagline.trim() : '';
  const platform = typeof body.platform === 'string' ? body.platform.trim() : '';
  const accentColor =
    typeof body.accentColor === 'string' ? body.accentColor.trim() : 'Cobalt Blue';
  const notes = typeof body.notes === 'string' ? body.notes.trim() : '';
  const rawAddons = Array.isArray(body.addonIds) ? body.addonIds : [];

  const bannerInfo = BANNER_PRICING[bannerId];
  if (!bannerInfo) {
    res.status(400).json({ error: 'Please select a valid banner pack.' });
    return;
  }
  if (channelTitle.length < 2 || channelTitle.length > 40) {
    res
      .status(400)
      .json({ error: 'Channel or Gamer Tag name must be 2–40 characters.' });
    return;
  }
  if (tagline.length > 60) {
    res.status(400).json({ error: 'Tagline must be 60 characters or less.' });
    return;
  }
  if (!PLATFORM_OPTIONS.has(platform)) {
    res.status(400).json({ error: 'Please select a valid platform format.' });
    return;
  }
  if (notes.length > 500) {
    res.status(400).json({ error: 'Notes must be 500 characters or less.' });
    return;
  }

  const validAddons = Array.from(
    new Set(
      rawAddons.filter(
        (id): id is string => typeof id === 'string' && id in ADDON_PRICING
      )
    )
  );

  const bundleDiscountOrExtra = platform === 'Full Streamer Bundle' ? 20 : 0;
  const addonsTotal = validAddons.reduce(
    (sum, id) => sum + ADDON_PRICING[id],
    0
  );
  const totalUsd = bannerInfo.priceUsd + bundleDiscountOrExtra + addonsTotal;

  const store = ensureStore();
  const order: StoredOrder = {
    id: `ORD-${crypto.randomBytes(3).toString('hex').toUpperCase()}`,
    userId: req.authUser!.id,
    userName: req.authUser!.name,
    userEmail: req.authUser!.email,
    bannerId,
    bannerTitle: bannerInfo.title,
    channelTitle,
    tagline,
    platform,
    accentColor: accentColor.slice(0, 30),
    addonIds: validAddons,
    notes,
    totalUsd,
    status: 'Queued for Design',
    createdAt: new Date().toISOString(),
  };

  store.orders.push(order);
  saveStore(store);

  res.status(201).json({ order });
});

async function startServer() {
  const distDir = path.resolve(process.cwd(), 'dist');
  const distIndex = path.resolve(distDir, 'index.html');
  const isDevLifecycle = process.env.npm_lifecycle_event === 'dev';
  const useViteDev =
    isDevLifecycle ||
    (process.env.NODE_ENV !== 'production' && !fs.existsSync(distIndex));

  if (useViteDev) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(distIndex);
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Adeel Banners server listening on port ${PORT}`);
  });
}

startServer();
