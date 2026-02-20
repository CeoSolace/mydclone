/*
 * Simplified Discord clone backend (single-file version)
 * - MongoDB (Mongoose)
 * - Email + password auth (JWT)
 * - Guilds (servers), categories, channels, DMs
 * - Roles/permissions + basic moderation slash commands
 * - Cloudinary uploads (avatars, guild images, attachments)
 * - Socket.IO realtime messaging
 * - AES-256-GCM encryption at rest for messages
 * - Serves React build from /client/dist (single Render service)
 */

require('dotenv').config();

const path = require('path');
const fs = require('fs');
const http = require('http');
const express = require('express');
const mongoose = require('mongoose');
const { v2: cloudinary } = require('cloudinary');
const multer = require('multer');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { Server } = require('socket.io');

/* ------------------------------------------------------------------------- */
/*                    Environment and external service setup                */
/* ------------------------------------------------------------------------- */

// MongoDB connection
const MONGODB_URI =
  process.env.MONGODB_URI || 'mongodb://localhost:27017/discord_clone';

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

mongoose.connection.on('error', (err) => console.error('MongoDB error:', err));

// Cloudinary configuration
cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.CLOUD_API_KEY,
  api_secret: process.env.CLOUD_API_SECRET,
});

// JWT secret
const JWT_SECRET = process.env.JWT_SECRET || 'change_me';

/* ------------------------------------------------------------------------- */
/*                               Mongoose models                            */
/* ------------------------------------------------------------------------- */

// User model
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  username: { type: String },
  salt: { type: String, required: true },
  passwordHash: { type: String, required: true },
  avatar: { type: String }, // Cloudinary URL
  isPlatformAdmin: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
});
const User = mongoose.model('User', userSchema);

// Guild (server) model
const guildSchema = new mongoose.Schema({
  name: { type: String, required: true },
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  image: { type: String }, // Cloudinary URL
  createdAt: { type: Date, default: Date.now },
});
const Guild = mongoose.model('Guild', guildSchema);

// Membership: user role within a guild
const membershipSchema = new mongoose.Schema({
  guild: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Guild',
    required: true,
  },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  role: {
    type: String,
    enum: ['owner', 'admin', 'moderator', 'member'],
    default: 'member',
  },
});
const Membership = mongoose.model('Membership', membershipSchema);

// Category within a guild
const categorySchema = new mongoose.Schema({
  name: { type: String, required: true },
  guild: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Guild',
    required: true,
  },
});
const Category = mongoose.model('Category', categorySchema);

// Channel: can be guild channel or DM thread
const channelSchema = new mongoose.Schema({
  name: { type: String },
  guild: { type: mongoose.Schema.Types.ObjectId, ref: 'Guild' },
  category: { type: mongoose.Schema.Types.ObjectId, ref: 'Category' },
  isDM: { type: Boolean, default: false },
  participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  encryptionKey: { type: String, required: true }, // base64(32 bytes)
  createdAt: { type: Date, default: Date.now },
});
const Channel = mongoose.model('Channel', channelSchema);

// Message: stores encrypted payload
const messageSchema = new mongoose.Schema({
  channel: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Channel',
    required: true,
  },
  author: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  encrypted: { type: String, required: true }, // hex
  iv: { type: String, required: true }, // hex
  tag: { type: String, required: true }, // hex
  createdAt: { type: Date, default: Date.now },
});
const Message = mongoose.model('Message', messageSchema);

/* ------------------------------------------------------------------------- */
/*                               Helpers & auth                             */
/* ------------------------------------------------------------------------- */

function derivePassword(password) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(password, salt, 32);
  return { salt: salt.toString('hex'), passwordHash: key.toString('hex') };
}

function verifyPassword(password, saltHex, hashHex) {
  const salt = Buffer.from(saltHex, 'hex');
  const key = crypto.scryptSync(password, salt, 32);
  return crypto.timingSafeEqual(key, Buffer.from(hashHex, 'hex'));
}

function generateToken(user) {
  return jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
}

function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Missing authorization' });
  const token = authHeader.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.id;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Role permissions
const ROLE_PERMS = {
  owner: { read: true, send: true, manage: true, moderate: true },
  admin: { read: true, send: true, manage: true, moderate: true },
  moderator: { read: true, send: true, manage: false, moderate: true },
  member: { read: true, send: true, manage: false, moderate: false },
};

async function hasPerm(userId, guildId, perm) {
  const guild = await Guild.findById(guildId);
  if (!guild) return false;
  if (String(guild.owner) === String(userId)) return true;
  const membership = await Membership.findOne({ guild: guildId, user: userId });
  if (!membership) return false;
  return !!(ROLE_PERMS[membership.role] && ROLE_PERMS[membership.role][perm]);
}

// AES-256-GCM encryption helpers (at-rest encryption)
function encrypt(plaintext, keyBase64) {
  const key = Buffer.from(keyBase64, 'base64');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag();
  return { encrypted, iv: iv.toString('hex'), tag: tag.toString('hex') };
}

function decrypt(encrypted, ivHex, tagHex, keyBase64) {
  const key = Buffer.from(keyBase64, 'base64');
  const iv = Buffer.from(ivHex, 'hex');
  const tag = Buffer.from(tagHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

/* ------------------------------------------------------------------------- */
/*                            Express application                            */
/* ------------------------------------------------------------------------- */

const app = express();
app.use(cors());
app.use(express.json());

// Multer storage (temporary local); Cloudinary is the real storage.
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const tempDir = path.join(__dirname, '..', 'tmp');
    fs.mkdirSync(tempDir, { recursive: true });
    cb(null, tempDir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  },
});
const upload = multer({ storage });

// Health check
app.get('/api/ping', (req, res) => {
  res.json({ status: 'ok' });
});

/*
 * Ensure the platform admin user (ceosolace) and the global guild exist.
 * The global guild is automatically joined by all users upon registration and
 * is owned by the platform admin.
 *
 * NOTE: "Platform ban" is not fully implemented in this file (would require a
 * DB flag + checks on auth/socket). This only ensures ownership/admin status.
 */
async function ensureGlobalGuild() {
  // Create or find the platform admin user
  let admin = await User.findOne({ email: 'ceosolace@example.com' });
  if (!admin) {
    // Change this password immediately after first deploy by logging in and updating.
    const { salt, passwordHash } = derivePassword('changeme');
    admin = await User.create({
      email: 'ceosolace@example.com',
      username: 'CeoSolace',
      salt,
      passwordHash,
      isPlatformAdmin: true,
    });
  }

  // Create or find the global guild
  let guild = await Guild.findOne({ name: 'Ceosolace Official' });
  if (!guild) {
    guild = await Guild.create({
      name: 'Ceosolace Official',
      owner: admin._id,
      image: null,
    });
    await Membership.create({ guild: guild._id, user: admin._id, role: 'owner' });
  }

  return { admin, guild };
}

// Registration
app.post('/api/register', async (req, res) => {
  try {
    const { email, password, username } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: 'Email and password required' });

    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ error: 'Email already registered' });

    const { salt, passwordHash } = derivePassword(password);
    const user = await User.create({
      email,
      username: username || email.split('@')[0],
      salt,
      passwordHash,
    });

    // Create personal guild for user
    const personalGuild = await Guild.create({
      name: `${user.username}'s Server`,
      owner: user._id,
    });
    await Membership.create({ guild: personalGuild._id, user: user._id, role: 'owner' });

    // Ensure global guild exists and join user
    const { guild: globalGuild } = await ensureGlobalGuild();
    await Membership.create({ guild: globalGuild._id, user: user._id, role: 'member' });

    const token = generateToken(user);
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !verifyPassword(password, user.salt, user.passwordHash)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = generateToken(user);
    res.json({ token });
  } catch {
    res.status(500).json({ error: 'Login failed' });
  }
});

// Current user
app.get('/api/me', authMiddleware, async (req, res) => {
  const user = await User.findById(req.userId).select('-passwordHash -salt');
  res.json(user);
});

// List guilds for user
app.get('/api/guilds', authMiddleware, async (req, res) => {
  const memberships = await Membership.find({ user: req.userId });
  const guildIds = memberships.map((m) => m.guild);
  const guilds = await Guild.find({ _id: { $in: guildIds } });
  res.json(guilds);
});

// Create guild
app.post('/api/guilds', authMiddleware, async (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });

  const guild = await Guild.create({ name, owner: req.userId });
  await Membership.create({ guild: guild._id, user: req.userId, role: 'owner' });
  res.json(guild);
});

// Create category
app.post('/api/guilds/:guildId/categories', authMiddleware, async (req, res) => {
  const { guildId } = req.params;
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });
  if (!(await hasPerm(req.userId, guildId, 'manage')))
    return res.status(403).json({ error: 'Forbidden' });

  const category = await Category.create({ name, guild: guildId });
  res.json(category);
});

// List categories
app.get('/api/guilds/:guildId/categories', authMiddleware, async (req, res) => {
  const { guildId } = req.params;
  const categories = await Category.find({ guild: guildId });
  res.json(categories);
});

// Create channel
app.post('/api/categories/:categoryId/channels', authMiddleware, async (req, res) => {
  const { categoryId } = req.params;
  const { name } = req.body;

  const category = await Category.findById(categoryId);
  if (!category) return res.status(404).json({ error: 'Category not found' });
  if (!(await hasPerm(req.userId, category.guild, 'manage')))
    return res.status(403).json({ error: 'Forbidden' });

  const key = crypto.randomBytes(32).toString('base64');
  const channel = await Channel.create({
    name,
    guild: category.guild,
    category: categoryId,
    encryptionKey: key,
  });

  res.json(channel);
});

// List channels by category
app.get('/api/categories/:categoryId/channels', authMiddleware, async (req, res) => {
  const { categoryId } = req.params;
  const channels = await Channel.find({ category: categoryId });
  res.json(channels);
});

// Create DM
app.post('/api/dms', authMiddleware, async (req, res) => {
  const { otherEmail } = req.body;
  const other = await User.findOne({ email: otherEmail });
  if (!other) return res.status(404).json({ error: 'User not found' });

  let channel = await Channel.findOne({
    isDM: true,
    participants: { $all: [req.userId, other._id] },
  });

  if (!channel) {
    const key = crypto.randomBytes(32).toString('base64');
    channel = await Channel.create({
      isDM: true,
      participants: [req.userId, other._id],
      encryptionKey: key,
    });
  }

  res.json(channel);
});

// List DMs
app.get('/api/dms', authMiddleware, async (req, res) => {
  const channels = await Channel.find({
    isDM: true,
    participants: { $in: [req.userId] },
  });
  res.json(channels);
});

// Get messages (decrypted)
app.get('/api/channels/:channelId/messages', authMiddleware, async (req, res) => {
  const { channelId } = req.params;
  const channel = await Channel.findById(channelId);
  if (!channel) return res.status(404).json({ error: 'Channel not found' });

  if (channel.isDM) {
    if (!channel.participants.some((p) => String(p) === String(req.userId))) {
      return res.status(403).json({ error: 'Not a participant' });
    }
  } else {
    if (!(await hasPerm(req.userId, channel.guild, 'read')))
      return res.status(403).json({ error: 'Forbidden' });
  }

  const msgs = await Message.find({ channel: channelId }).sort({ createdAt: 1 });
  const result = msgs.map((m) => {
    try {
      const content = decrypt(m.encrypted, m.iv, m.tag, channel.encryptionKey);
      return { id: m._id, author: m.author, content, createdAt: m.createdAt };
    } catch {
      return { id: m._id, author: m.author, content: '[decrypt error]', createdAt: m.createdAt };
    }
  });

  res.json(result);
});

// Upload any attachment to Cloudinary (field: file)
app.post('/api/upload', authMiddleware, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'Missing file' });

    const uploadRes = await cloudinary.uploader.upload(req.file.path, {
      folder: 'discord-clone',
    });

    fs.unlink(req.file.path, () => {});
    res.json({ url: uploadRes.secure_url, publicId: uploadRes.public_id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Upload failed' });
  }
});

// Update user settings (username + avatar)
app.post('/api/user/settings', authMiddleware, upload.single('avatar'), async (req, res) => {
  try {
    const { username } = req.body;
    const user = await User.findById(req.userId);

    if (username) user.username = username;

    if (req.file) {
      const uploadRes = await cloudinary.uploader.upload(req.file.path, {
        folder: 'avatars',
      });
      user.avatar = uploadRes.secure_url;
      fs.unlink(req.file.path, () => {});
    }

    await user.save();
    res.json({
      message: 'Updated',
      user: { username: user.username, avatar: user.avatar },
    });
  } catch {
    res.status(500).json({ error: 'Settings update failed' });
  }
});

// Update guild settings (owner only)
app.post('/api/guilds/:guildId/settings', authMiddleware, upload.single('image'), async (req, res) => {
  const { guildId } = req.params;
  const { name } = req.body;

  const guild = await Guild.findById(guildId);
  if (!guild) return res.status(404).json({ error: 'Guild not found' });
  if (String(guild.owner) !== String(req.userId))
    return res.status(403).json({ error: 'Only owner can update settings' });

  if (name) guild.name = name;

  if (req.file) {
    const uploadRes = await cloudinary.uploader.upload(req.file.path, {
      folder: 'guilds',
    });
    guild.image = uploadRes.secure_url;
    fs.unlink(req.file.path, () => {});
  }

  await guild.save();
  res.json({ message: 'Guild updated', guild });
});

/* ------------------------------------------------------------------------- */
/*                       HTTP server and Socket.IO setup                     */
/* ------------------------------------------------------------------------- */

const httpServer = http.createServer(app);
const io = new Server(httpServer, {
  cors: { origin: '*', methods: ['GET', 'POST'] },
});

// In-memory ban/mute state (guild-level)
const banned = new Map();
const muted = new Map();

function ensureSet(map, key) {
  let set = map.get(key);
  if (!set) {
    set = new Set();
    map.set(key, set);
  }
  return set;
}

// Authenticate socket
io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth.token || socket.handshake.query.token;
    if (!token) return next(new Error('Missing token'));
    const payload = jwt.verify(token, JWT_SECRET);
    socket.userId = payload.id;
    socket.user = await User.findById(socket.userId);
    next();
  } catch {
    next(new Error('Authentication failed'));
  }
});

// Handle connections
io.on('connection', (socket) => {
  // Join guild room and send guild data
  socket.on('joinGuild', async (guildId) => {
    try {
      const isMember = await Membership.findOne({ guild: guildId, user: socket.userId });
      const guild = await Guild.findById(guildId);
      if (!guild || (!isMember && String(guild.owner) !== String(socket.userId))) {
        socket.emit('errorMessage', 'Not a guild member');
        return;
      }

      socket.join(`guild:${guildId}`);

      const categories = await Category.find({ guild: guildId });
      const catIds = categories.map((c) => c._id);

      const channels = await Channel.find({
        $or: [{ guild: guildId }, { category: { $in: catIds } }],
      });

      socket.emit('guildData', { categories, channels });
    } catch {
      socket.emit('errorMessage', 'Join guild failed');
    }
  });

  // Join channel room and send history
  socket.on('joinChannel', async (channelId) => {
    const channel = await Channel.findById(channelId);
    if (!channel) {
      socket.emit('errorMessage', 'Channel not found');
      return;
    }

    if (channel.isDM) {
      if (!channel.participants.some((p) => String(p) === String(socket.userId))) {
        socket.emit('errorMessage', 'Not a DM participant');
        return;
      }
    } else {
      if (!(await hasPerm(socket.userId, channel.guild, 'read'))) {
        socket.emit('errorMessage', 'No read access');
        return;
      }
      const bannedSet = banned.get(String(channel.guild));
      if (bannedSet && bannedSet.has(String(socket.userId))) {
        socket.emit('errorMessage', 'Banned from guild');
        return;
      }
    }

    socket.join(`channel:${channelId}`);
    socket.emit('channelKey', { channelId, key: channel.encryptionKey });

    const msgs = await Message.find({ channel: channelId }).sort({ createdAt: 1 });
    const history = msgs.map((m) => {
      try {
        const content = decrypt(m.encrypted, m.iv, m.tag, channel.encryptionKey);
        return { id: m._id, author: m.author, content, createdAt: m.createdAt };
      } catch {
        return { id: m._id, author: m.author, content: '[decrypt error]', createdAt: m.createdAt };
      }
    });

    socket.emit('messageHistory', { channelId, messages: history });
  });

  socket.on('leaveChannel', (channelId) => {
    socket.leave(`channel:${channelId}`);
  });

  // Send message or run slash command
  socket.on('sendMessage', async ({ channelId, content }) => {
    const channel = await Channel.findById(channelId);
    if (!channel) {
      socket.emit('errorMessage', 'Channel not found');
      return;
    }

    if (channel.isDM) {
      if (!channel.participants.some((p) => String(p) === String(socket.userId))) {
        socket.emit('errorMessage', 'Not a DM participant');
        return;
      }
    } else {
      const bannedSet = banned.get(String(channel.guild));
      if (bannedSet && bannedSet.has(String(socket.userId))) {
        socket.emit('errorMessage', 'You are banned');
        return;
      }

      const mutedSet = muted.get(String(channel.guild));
      if (mutedSet && mutedSet.has(String(socket.userId))) {
        socket.emit('errorMessage', 'You are muted');
        return;
      }

      if (!(await hasPerm(socket.userId, channel.guild, 'send'))) {
        socket.emit('errorMessage', 'No send permission');
        return;
      }
    }

    if (!channel.isDM && typeof content === 'string' && content.startsWith('/')) {
      await handleCommand(content, socket, channel);
      return;
    }

    const enc = encrypt(String(content || ''), channel.encryptionKey);
    const msg = await Message.create({
      channel: channelId,
      author: socket.userId,
      encrypted: enc.encrypted,
      iv: enc.iv,
      tag: enc.tag,
    });

    const payload = { id: msg._id, author: socket.userId, content, createdAt: msg.createdAt };
    io.to(`channel:${channelId}`).emit('newMessage', { channelId, message: payload });
  });
});

// Slash command handler
async function handleCommand(cmdStr, socket, channel) {
  const parts = cmdStr.trim().split(/\s+/);
  const cmd = parts[0].toLowerCase();
  const guildId = channel.guild;
  const userId = socket.userId;

  const hasMod = await hasPerm(userId, guildId, 'moderate');
  if (!hasMod) {
    socket.emit('errorMessage', 'Insufficient permission');
    return;
  }

  switch (cmd) {
    case '/ban': {
      const email = parts[1];
      const user = await User.findOne({ email });
      if (!user) {
        socket.emit('errorMessage', 'User not found');
        break;
      }
      ensureSet(banned, String(guildId)).add(String(user._id));
      socket.emit('infoMessage', `${email} banned`);
      break;
    }
    case '/unban': {
      const email = parts[1];
      const user = await User.findOne({ email });
      if (!user) {
        socket.emit('errorMessage', 'User not found');
        break;
      }
      ensureSet(banned, String(guildId)).delete(String(user._id));
      socket.emit('infoMessage', `${email} unbanned`);
      break;
    }
    case '/mute': {
      const email = parts[1];
      const user = await User.findOne({ email });
      if (!user) {
        socket.emit('errorMessage', 'User not found');
        break;
      }
      ensureSet(muted, String(guildId)).add(String(user._id));
      socket.emit('infoMessage', `${email} muted`);
      break;
    }
    case '/unmute': {
      const email = parts[1];
      const user = await User.findOne({ email });
      if (!user) {
        socket.emit('errorMessage', 'User not found');
        break;
      }
      ensureSet(muted, String(guildId)).delete(String(user._id));
      socket.emit('infoMessage', `${email} unmuted`);
      break;
    }
    case '/role': {
      const email = parts[1];
      const newRole = parts[2];
      if (!['member', 'moderator', 'admin'].includes(newRole)) {
        socket.emit('errorMessage', 'Invalid role');
        break;
      }
      const user = await User.findOne({ email });
      if (!user) {
        socket.emit('errorMessage', 'User not found');
        break;
      }
      let mem = await Membership.findOne({ guild: guildId, user: user._id });
      if (!mem) mem = await Membership.create({ guild: guildId, user: user._id, role: newRole });
      else {
        mem.role = newRole;
        await mem.save();
      }
      socket.emit('infoMessage', `${email} is now ${newRole}`);
      break;
    }
    default:
      socket.emit('errorMessage', 'Unknown command');
  }
}

/* ------------------------------------------------------------------------- */
/*                      Serve React build from same service                  */
/* ------------------------------------------------------------------------- */
/*
 * This fixes "Cannot GET /" on Render when you deploy only one service.
 * Build client first (Vite) so client/dist exists:
 *   npm install --prefix server && npm install --prefix client && npm run build --prefix client
 * Then start server:
 *   npm start --prefix server
 */
const clientDistPath = path.join(__dirname, '../../client/dist');
app.use(express.static(clientDistPath));

// SPA fallback for React Router
app.get('*', (req, res) => {
  res.sendFile(path.join(clientDistPath, 'index.html'));
});

/* ------------------------------------------------------------------------- */
/*                                  Startup                                 */
/* ------------------------------------------------------------------------- */

ensureGlobalGuild().then(() => console.log('Global guild ready'));

const PORT = process.env.PORT || 3000;
httpServer.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
