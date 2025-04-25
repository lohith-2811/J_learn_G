import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { initDB, getDB } from './db.js';
import cors from 'cors';

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();
const PORT = process.env.FULL_PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;

// In production, use Redis instead of in-memory Set
const activeTokens = new Set();
let googleClient = null;

// Try to initialize Google Auth if configured
if (GOOGLE_CLIENT_ID) {
  try {
    const { OAuth2Client } = await import('google-auth-library');
    googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);
    console.log('Google Sign-In initialized successfully');
  } catch (err) {
    console.warn('Google Auth Library not found. Google Sign-In will be disabled.');
  }
} else {
  console.warn('GOOGLE_CLIENT_ID not configured. Google Sign-In disabled.');
}

// Middleware
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Helper function to get current IST time
function getISTTimestamp() {
  const now = new Date();
  const ISTOffset = 330; // IST is UTC+5:30 (5*60 + 30 = 330 minutes)
  const ISTTime = new Date(now.getTime() + (ISTOffset - now.getTimezoneOffset()) * 60000);
  return ISTTime.toISOString().replace('T', ' ').replace('.000Z', '');
}

// Health check endpoint with IST timestamp
app.get('/', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    message: 'JLearn API with persistent sessions',
    timestamp: getISTTimestamp(),
    features: {
      googleSignIn: !!googleClient,
      persistentSessions: true
    }
  });
});

// Initialize database
(async () => {
  try {
    await initDB();
    console.log('Database initialized successfully at', getISTTimestamp());
  } catch (err) {
    console.error('Database initialization failed at', getISTTimestamp(), ':', err);
    process.exit(1);
  }
})();

// Enhanced Authentication Middleware
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization || req.query.token;
  
  if (!authHeader) {
    return res.status(401).json({ 
      error: 'Authorization header missing',
      timestamp: getISTTimestamp()
    });
  }

  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;

  // Check if token was invalidated
  if (!activeTokens.has(token)) {
    return res.status(403).json({ 
      error: 'Session terminated. Please login again.',
      timestamp: getISTTimestamp()
    });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.error('JWT verification error at', getISTTimestamp(), ':', err);
      return res.status(403).json({ 
        error: 'Invalid or malformed token',
        timestamp: getISTTimestamp()
      });
    }
    req.user = user;
    next();
  });
};

// Google Sign-In Endpoint
app.post('/auth/google', async (req, res) => {
  if (!googleClient) {
    return res.status(501).json({
      success: false,
      error: 'Google Sign-In is not configured on this server',
      timestamp: getISTTimestamp()
    });
  }

  const { token: googleToken } = req.body;

  if (!googleToken) {
    return res.status(400).json({ 
      error: 'Google token is required',
      timestamp: getISTTimestamp()
    });
  }

  try {
    // Verify Google token
    const ticket = await googleClient.verifyIdToken({
      idToken: googleToken,
      audience: GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    const { email, name: username } = payload;
    const createdAt = getISTTimestamp();

    const db = getDB();

    // Check if user exists
    let user = await db.execute({
      sql: 'SELECT user_id, username, email FROM user_profiles WHERE email = ?',
      args: [email],
    });

    let userId;

    if (user.rows.length === 0) {
      // Create new user if doesn't exist
      const result = await db.execute({
        sql: 'INSERT INTO user_profiles (username, email, password_hash, is_google_auth, created_at) VALUES (?, ?, ?, ?, ?)',
        args: [username, email, 'google_oauth', 1, createdAt],
      });
      userId = Number(result.lastInsertRowid);

      // Initialize achievements
      await db.execute({
        sql: 'INSERT INTO user_achievements (user_id, xp_points) VALUES (?, ?)',
        args: [userId, 0],
      });
    } else {
      userId = user.rows[0].user_id;
      // Update last login
      await db.execute({
        sql: 'UPDATE user_profiles SET last_login = ? WHERE user_id = ?',
        args: [getISTTimestamp(), userId],
      });
    }

    // Generate JWT
    const token = jwt.sign(
      { id: userId, email, username },
      JWT_SECRET
    );

    activeTokens.add(token);

    res.json({
      success: true,
      token,
      user: { 
        id: userId, 
        username, 
        email,
        isGoogleAuth: true
      },
      isNewUser: user.rows.length === 0,
      timestamp: getISTTimestamp()
    });

  } catch (err) {
    console.error('Google auth error at', getISTTimestamp(), ':', err);
    res.status(401).json({ 
      error: 'Invalid Google token',
      timestamp: getISTTimestamp()
    });
  }
});

// Regular Email/Password Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const loginTime = getISTTimestamp();

  if (!email || !password) {
    return res.status(400).json({ 
      error: 'Email and password are required',
      timestamp: loginTime
    });
  }

  try {
    const db = getDB();
    const result = await db.execute({
      sql: 'SELECT user_id, username, email, password_hash, is_google_auth FROM user_profiles WHERE email = ?',
      args: [email],
    });

    const user = result.rows[0];
    if (!user) {
      return res.status(401).json({ 
        error: 'Invalid credentials',
        timestamp: loginTime
      });
    }

    // Check if user registered via Google
    if (user.is_google_auth) {
      return res.status(403).json({ 
        error: 'This account uses Google Sign-In. Please sign in with Google.',
        timestamp: loginTime
      });
    }

    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(401).json({ 
        error: 'Invalid credentials',
        timestamp: loginTime
      });
    }

    // Update last login
    await db.execute({
      sql: 'UPDATE user_profiles SET last_login = ? WHERE user_id = ?',
      args: [loginTime, user.user_id],
    });

    const token = jwt.sign(
      { id: user.user_id, email: user.email, username: user.username },
      JWT_SECRET
    );

    activeTokens.add(token);
    
    res.json({ 
      success: true, 
      token,
      user: {
        id: user.user_id,
        username: user.username,
        email: user.email,
        isGoogleAuth: false
      },
      timestamp: loginTime
    });
  } catch (err) {
    console.error('Login error at', getISTTimestamp(), ':', err);
    res.status(500).json({ 
      error: 'Login failed',
      timestamp: getISTTimestamp()
    });
  }
});

// Email/Password Signup
app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;
  const signupTime = getISTTimestamp();

  if (!email || !username || !password) {
    return res.status(400).json({ 
      error: 'All fields are required',
      fields: { email: !email, username: !username, password: !password },
      timestamp: signupTime
    });
  }

  try {
    const db = getDB();
    
    // Check if email exists with Google auth
    const existing = await db.execute({
      sql: 'SELECT is_google_auth FROM user_profiles WHERE email = ?',
      args: [email],
    });

    if (existing.rows.length > 0 && existing.rows[0].is_google_auth) {
      return res.status(409).json({ 
        error: 'Email already registered with Google. Please sign in with Google.',
        timestamp: signupTime
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await db.execute({
      sql: 'INSERT INTO user_profiles (username, email, password_hash, is_google_auth, created_at) VALUES (?, ?, ?, ?, ?)',
      args: [username, email, hashedPassword, 0, signupTime],
    });

    const userId = Number(result.lastInsertRowid);
    await db.execute({
      sql: 'INSERT INTO user_achievements (user_id, xp_points) VALUES (?, ?)',
      args: [userId, 0],
    });

    res.status(201).json({ 
      success: true, 
      userId,
      timestamp: signupTime
    });
  } catch (err) {
    console.error('Signup error at', getISTTimestamp(), ':', err);
    if (err.message?.includes('UNIQUE')) {
      return res.status(409).json({ 
        error: 'Email already exists',
        timestamp: getISTTimestamp()
      });
    }
    res.status(500).json({ 
      error: 'Registration failed',
      timestamp: getISTTimestamp()
    });
  }
});

// Explicit logout endpoint
app.post('/logout', authenticateJWT, (req, res) => {
  const token = req.headers.authorization.slice(7);
  const logoutTime = getISTTimestamp();
  
  // Remove token from active set
  activeTokens.delete(token);
  
  res.json({ 
    success: true,
    message: 'Logged out successfully. Token invalidated.',
    timestamp: logoutTime
  });
});

// Emergency token invalidation (for app uninstall/data clear)
app.post('/invalidate-all', async (req, res) => {
  const { email, password } = req.body;
  const invalidationTime = getISTTimestamp();

  if (!email || !password) {
    return res.status(400).json({ 
      error: 'Email and password are required',
      timestamp: invalidationTime
    });
  }

  try {
    const db = getDB();
    const result = await db.execute({
      sql: 'SELECT user_id FROM user_profiles WHERE email = ?',
      args: [email],
    });

    const user = result.rows[0];
    if (!user) {
      return res.status(404).json({ 
        error: 'User not found',
        timestamp: invalidationTime
      });
    }

    // Verify password
    const pwResult = await db.execute({
      sql: 'SELECT password_hash FROM user_profiles WHERE user_id = ?',
      args: [user.user_id],
    });

    const isMatch = await bcrypt.compare(password, pwResult.rows[0].password_hash);
    if (!isMatch) {
      return res.status(401).json({ 
        error: 'Invalid credentials',
        timestamp: invalidationTime
      });
    }

    // In production: Query all tokens for this user from Redis/db and remove
    activeTokens.clear();

    res.json({ 
      success: true,
      message: 'All sessions invalidated successfully',
      timestamp: invalidationTime
    });
  } catch (err) {
    console.error('Invalidation error at', getISTTimestamp(), ':', err);
    res.status(500).json({ 
      error: 'Session invalidation failed',
      timestamp: getISTTimestamp()
    });
  }
});

// Protected progress update endpoint
app.post('/progress', authenticateJWT, async (req, res) => {
  const { language, level, module_id, lesson_id, is_completed, current_question_index } = req.body;
  const updateTime = getISTTimestamp();

  if (!language || level === undefined || module_id === undefined || lesson_id === undefined) {
    return res.status(400).json({ 
      error: 'Missing required fields',
      timestamp: updateTime
    });
  }

  try {
    const db = getDB();
    const bitPosition = 1 << (lesson_id - 1);
    const maskUpdate = is_completed ? bitPosition : 0;

    await db.execute({
      sql: `
        INSERT INTO user_module_progress 
          (user_id, language, level, module_id, completion_mask, 
           current_lesson_id, current_question_index, last_updated)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id, language, level, module_id) 
        DO UPDATE SET
          completion_mask = CASE 
            WHEN ? = 0 THEN completion_mask & ~?
            ELSE completion_mask | ?
          END,
          current_lesson_id = excluded.current_lesson_id,
          current_question_index = excluded.current_question_index,
          last_updated = ?
      `,
      args: [
        req.user.id,
        language,
        level,
        module_id,
        maskUpdate,
        lesson_id,
        current_question_index || 0,
        updateTime,
        maskUpdate,
        bitPosition,
        bitPosition,
        updateTime
      ],
    });

    res.json({ 
      success: true,
      message: 'Progress updated successfully',
      timestamp: updateTime
    });
  } catch (err) {
    console.error('Progress update error at', getISTTimestamp(), ':', err);
    res.status(500).json({ 
      error: 'Failed to update progress',
      timestamp: getISTTimestamp()
    });
  }
});


// Progress Tracking Endpoints
app.get('/progress', authenticateJWT, async (req, res) => {
  try {
    const db = getDB();
    const result = await db.execute({
      sql: 'SELECT * FROM user_progress WHERE user_id = ?',
      args: [req.user.id],
    });

    res.json({
      success: true,
      progress: result.rows
    });
  } catch (err) {
    console.error('Progress fetch error:', err);
    res.status(500).json({
      error: 'Failed to fetch progress',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});

// Get user profile
app.get('/profile', authenticateJWT, async (req, res) => {
  try {
    const db = getDB();
    const result = await db.execute({
      sql: 'SELECT user_id, username, email, is_google_auth, created_at, last_login FROM user_profiles WHERE user_id = ?',
      args: [req.user.id],
    });

    const user = result.rows[0];
    if (!user) {
      return res.status(404).json({ 
        error: 'User not found',
        timestamp: getISTTimestamp()
      });
    }

    res.json({
      success: true,
      profile: {
        id: user.user_id,
        username: user.username,
        email: user.email,
        isGoogleAuth: user.is_google_auth,
        createdAt: user.created_at,
        lastLogin: user.last_login
      },
      timestamp: getISTTimestamp()
    });
  } catch (err) {
    console.error('Profile fetch error at', getISTTimestamp(), ':', err);
    res.status(500).json({ 
      error: 'Failed to fetch profile',
      timestamp: getISTTimestamp()
    });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server started at ${getISTTimestamp()} on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log('Features enabled:');
  console.log('- Persistent JWT sessions');
  console.log('- Google Sign-In:', googleClient ? 'Enabled' : 'Disabled');
  console.log('- Indian Standard Time (IST) timestamps');
  console.log('- Bitmask progress tracking');
});
