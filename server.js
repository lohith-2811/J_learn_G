import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { initDB, getDB } from './db.js';
import cors from 'cors';
import nodemailer from 'nodemailer';
import fs from 'fs';
import admin from 'firebase-admin';

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;
const REQUIRE_EMAIL_VERIFICATION = process.env.REQUIRE_EMAIL_VERIFICATION === 'true';

// In production, use Redis instead of in-memory Set
const activeTokens = new Set();

// Firebase Admin SDK Initialization
let firebaseCredentials;
try {
  firebaseCredentials = JSON.parse(process.env.FIREBASE_CREDENTIALS);
} catch (error) {
  console.error("Error parsing FIREBASE_CREDENTIALS:", error);
  process.exit(1);
}

// Initialize Firebase Admin SDK
admin.initializeApp({
  credential: admin.credential.cert(firebaseCredentials)
});

const firebaseInitialized = true;

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
      googleSignIn: firebaseInitialized,
      persistentSessions: true,
      requireEmailVerification: REQUIRE_EMAIL_VERIFICATION,
      emailService: !!process.env.EMAIL_USER && !!process.env.EMAIL_PASS
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

// Email sender
export const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

export const sendOTP = async (to, otp, purpose = 'email verification') => {
  try {
    const subject = purpose === 'password reset' ? 'Reset Your JLearn Password' : 'Verify Your Email with Jairisys';
    const html = purpose === 'password reset'
      ? `<p>Your password reset OTP is: <strong>${otp}</strong></p><p>It will expire in 10 minutes.</p>`
      : `<p>Your OTP code is: <strong>${otp}</strong></p><p>It will expire in 10 minutes. Please verify within this time, or your account will be deleted.</p>`;

    const info = await transporter.sendMail({
      from: `"JLearn" <${process.env.EMAIL_USER}>`,
      to,
      subject,
      html,
    });
    console.log(`OTP email sent successfully to ${to} for ${purpose}. Message ID:`, info.messageId);
    return info;
  } catch (err) {
    console.error(`Failed to send OTP email to ${to} for ${purpose}:`, err);
    console.warn(`OTP for testing (check database or resend): ${otp}`);
    throw new Error(`Failed to send OTP: ${err.message}`);
  }
};

// Google Sign-In (Firebase Auth) Endpoint
app.post('/auth/google', async (req, res) => {
  if (!firebaseInitialized) {
    return res.status(501).json({
      success: false,
      error: 'Google Sign-In is not configured on this server',
      timestamp: getISTTimestamp()
    });
  }

  const { token: firebaseToken } = req.body;

  if (!firebaseToken) {
    return res.status(400).json({
      error: 'Firebase ID token is required',
      timestamp: getISTTimestamp()
    });
  }

  try {
    // Verify Firebase ID token
    const decodedToken = await admin.auth().verifyIdToken(firebaseToken);
    const { uid, email } = decodedToken;

    const db = getDB();

    // Check if user exists
    let user = await db.execute({
      sql: 'SELECT user_id, username, email FROM user_profiles WHERE email = ?',
      args: [email],
    });

    if (user.rows.length === 0) {
      return res.status(404).json({
        error: 'User not found. Please sign up first using email/password.',
        timestamp: getISTTimestamp()
      });
    }

    const userId = user.rows[0].user_id;
    const username = user.rows[0].username;

    // Update last login
    await db.execute({
      sql: 'UPDATE user_profiles SET last_login = ? WHERE user_id = ?',
      args: [getISTTimestamp(), userId],
    });

    // Generate JWT
    const appToken = jwt.sign(
      { id: userId, email, username },
      JWT_SECRET
    );

    activeTokens.add(appToken);

    res.json({
      success: true,
      token: appToken,
      user: {
        id: userId,
        username,
        email,
        isGoogleAuth: true
      },
      timestamp: getISTTimestamp()
    });

  } catch (err) {
    console.error('Firebase auth error at', getISTTimestamp(), ':', err);
    res.status(401).json({
      error: 'Invalid Firebase ID token',
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
      sql: 'SELECT user_id, username, email, password_hash, is_google_auth, is_verified FROM user_profiles WHERE email = ?',
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

    // Check email verification if required
    if (REQUIRE_EMAIL_VERIFICATION && !user.is_verified) {
      return res.status(403).json({
        error: 'Email not verified. Please verify your email to log in.',
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
        isGoogleAuth: false,
        isVerified: user.is_verified
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

  if (!username || !email || !password) {
    return res.status(400).json({ error: 'All fields are required', timestamp: signupTime });
  }

  try {
    const db = getDB();

    const checkUser = await db.execute({
      sql: 'SELECT * FROM user_profiles WHERE email = ?',
      args: [email],
    });

    if (checkUser.rows.length > 0) {
      return res.status(400).json({ error: 'Email already registered', timestamp: signupTime });
    }

    // Hash the password
    const passwordHash = await bcrypt.hash(password, 10);

    // Calculate expiration time (10 minutes from now)
    const expiresAt = Date.now() + 10 * 60 * 1000;

    // Insert user with expiration time
    await db.execute({
      sql: 'INSERT INTO user_profiles (username, email, password_hash, is_verified, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)',
      args: [username, email, passwordHash, false, signupTime, expiresAt],
    });

    // Generate and store OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await db.execute({
      sql: 'INSERT OR REPLACE INTO user_otp_verification (email, otp, expires_at, created_at) VALUES (?, ?, ?, ?)',
      args: [email, otp, expiresAt, signupTime],
    });

    // Schedule deletion of unverified user after 10 minutes
    setTimeout(async () => {
      try {
        const result = await db.execute({
          sql: 'SELECT is_verified FROM user_profiles WHERE email = ?',
          args: [email],
        });

        if (result.rows.length > 0 && !result.rows[0].is_verified) {
          await db.execute({
            sql: 'DELETE FROM user_profiles WHERE email = ?',
            args: [email],
          });
          await db.execute({
            sql: 'DELETE FROM user_otp_verification WHERE email = ?',
            args: [email],
          });
          console.log(`Deleted unverified user ${email} at ${getISTTimestamp()}`);
        }
      } catch (err) {
        console.error(`Error deleting unverified user ${email} at ${getISTTimestamp()}:`, err);
      }
    }, 10 * 60 * 1000); // 10 minutes

    try {
      await sendOTP(email, otp);
      res.status(200).json({
        success: true,
        message: 'Signup successful. OTP sent to your email. Please verify within 10 minutes.',
        timestamp: signupTime,
      });
    } catch (emailErr) {
      console.warn('Signup successful, but OTP email failed to send for', email);
      console.warn('OTP for testing (check database or resend):', otp);
      res.status(200).json({
        success: true,
        message: 'Signup successful, but OTP email failed to send. OTP logged to console and stored in database. Please verify within 10 minutes.',
        timestamp: signupTime,
      });
    }
  } catch (err) {
    console.error('Signup error at', signupTime, ':', err);
    res.status(500).json({ error: 'Signup failed: ' + err.message, timestamp: signupTime });
  }
});

// Verify OTP
app.post('/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  const verifyTime = getISTTimestamp();

  if (!email || !otp) {
    return res.status(400).json({ error: 'Email and OTP are required', timestamp: verifyTime });
  }

  try {
    const db = getDB();

    // Check if user exists
    const userResult = await db.execute({
      sql: 'SELECT user_id FROM user_profiles WHERE email = ?',
      args: [email],
    });

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found. Account may have been deleted due to unverified status.', timestamp: verifyTime });
    }

    const result = await db.execute({
      sql: 'SELECT otp, expires_at FROM user_otp_verification WHERE email = ?',
      args: [email],
    });

    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'No OTP found for this email', timestamp: verifyTime });
    }

    const storedOTP = result.rows[0].otp;
    const expiresAt = result.rows[0].expires_at;

    if (Date.now() > expiresAt) {
      // Delete user and OTP if expired
      await db.execute({
        sql: 'DELETE FROM user_profiles WHERE email = ?',
        args: [email],
      });
      await db.execute({
        sql: 'DELETE FROM user_otp_verification WHERE email = ?',
        args: [email],
      });
      return res.status(400).json({ error: 'OTP expired. Account deleted. Please sign up again.', timestamp: verifyTime });
    }

    if (otp !== storedOTP) {
      return res.status(400).json({ error: 'Invalid OTP', timestamp: verifyTime });
    }

    // Mark user as verified and clear expiration
    await db.execute({
      sql: 'UPDATE user_profiles SET is_verified = ?, expires_at = NULL WHERE email = ?',
      args: [true, email],
    });

    await db.execute({
      sql: 'DELETE FROM user_otp_verification WHERE email = ?',
      args: [email],
    });

    res.status(200).json({ success: true, message: 'Email verified successfully', timestamp: verifyTime });
  } catch (err) {
    console.error('Verification error at', verifyTime, ':', err);
    res.status(500).json({ error: 'OTP verification failed: ' + err.message, timestamp: verifyTime });
  }
});

// Forgot Password Endpoint
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  const requestTime = getISTTimestamp();

  if (!email) {
    return res.status(400).json({ error: 'Email is required', timestamp: requestTime });
  }

  try {
    const db = getDB();
    const result = await db.execute({
      sql: 'SELECT user_id, is_google_auth FROM user_profiles WHERE email = ?',
      args: [email],
    });

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Email not found', timestamp: requestTime });
    }

    const user = result.rows[0];
    if (user.is_google_auth) {
      return res.status(400).json({
        error: 'This account uses Google Sign-In. Password reset is not applicable.',
        timestamp: requestTime,
      });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes

    await db.execute({
      sql: 'INSERT OR REPLACE INTO user_otp_verification (email, otp, expires_at, created_at) VALUES (?, ?, ?, ?)',
      args: [email, otp, expiresAt, requestTime],
    });

    try {
      await sendOTP(email, otp, 'password reset');
      res.status(200).json({
        success: true,
        message: 'Password reset OTP sent to your email.',
        timestamp: requestTime,
      });
    } catch (emailErr) {
      console.warn('Password reset OTP generated, but email failed to send for', email);
      console.warn('OTP for testing (check database or resend):', otp);
      res.status(200).json({
        success: true,
        message: 'Password reset OTP generated, but email failed to send. OTP logged to console and stored in database. Please check or request a new OTP.',
        timestamp: requestTime,
      });
    }
  } catch (err) {
    console.error('Forgot password error at', requestTime, ':', err);
    res.status(500).json({ error: 'Failed to process password reset request: ' + err.message, timestamp: requestTime });
  }
});

// Reset Password Endpoint
app.post('/reset-password', async (req, res) => {
  const { email, otp, newPassword } = req.body;
  const resetTime = getISTTimestamp();

  if (!email || !otp || !newPassword) {
    return res.status(400).json({ error: 'Email, OTP, and new password are required', timestamp: resetTime });
  }

  try {
    const db = getDB();

    const otpResult = await db.execute({
      sql: 'SELECT otp, expires_at FROM user_otp_verification WHERE email = ?',
      args: [email],
    });

    if (otpResult.rows.length === 0) {
      return res.status(400).json({ error: 'No OTP found for this email', timestamp: resetTime });
    }

    const storedOTP = otpResult.rows[0].otp;
    const expiresAt = otpResult.rows[0].expires_at;

    if (Date.now() > expiresAt) {
      await db.execute({
        sql: 'DELETE FROM user_otp_verification WHERE email = ?',
        args: [email],
      });
      return res.status(400).json({ error: 'OTP expired', timestamp: resetTime });
    }

    if (otp !== storedOTP) {
      return res.status(400).json({ error: 'Invalid OTP', timestamp: resetTime });
    }

    const userResult = await db.execute({
      sql: 'SELECT user_id, is_google_auth FROM user_profiles WHERE email = ?',
      args: [email],
    });

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found', timestamp: resetTime });
    }

    const user = userResult.rows[0];
    if (user.is_google_auth) {
      return res.status(400).json({
        error: 'This account uses Google Sign-In. Password reset is not applicable.',
        timestamp: resetTime,
      });
    }

    const passwordHash = await bcrypt.hash(newPassword, 10);

    await db.execute({
      sql: 'UPDATE user_profiles SET password_hash = ? WHERE email = ?',
      args: [passwordHash, email],
    });

    await db.execute({
      sql: 'DELETE FROM user_otp_verification WHERE email = ?',
      args: [email],
    });

    // Invalidate all active tokens for this user
    const tokensToRemove = [...activeTokens].filter(token => {
      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        return decoded.email === email;
      } catch {
        return false;
      }
    });
    tokensToRemove.forEach(token => activeTokens.delete(token));

    res.status(200).json({
      success: true,
      message: 'Password reset successfully. All active sessions have been invalidated.',
      timestamp: resetTime,
    });
  } catch (err) {
    console.error('Reset password error at', resetTime, ':', err);
    res.status(500).json({ error: 'Failed to reset password: ' + err.message, timestamp: resetTime });
  }
});

// Resend OTP
app.post('/resend-otp', async (req, res) => {
  const { email } = req.body;
  const resendTime = getISTTimestamp();

  if (!email) {
    return res.status(400).json({ error: 'Email is required', timestamp: resendTime });
  }

  try {
    const db = getDB();

    const result = await db.execute({
      sql: 'SELECT is_verified, expires_at FROM user_profiles WHERE email = ?',
      args: [email],
    });

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found. Account may have been deleted due to unverified status.', timestamp: resendTime });
    }

    if (result.rows[0].is_verified) {
      return res.status(400).json({ error: 'Email already verified', timestamp: resendTime });
    }

    if (Date.now() > result.rows[0].expires_at) {
      // Delete user and OTP if expired
      await db.execute({
        sql: 'DELETE FROM user_profiles WHERE email = ?',
        args: [email],
      });
      await db.execute({
        sql: 'DELETE FROM user_otp_verification WHERE email = ?',
        args: [email],
      });
      return res.status(400).json({ error: 'Verification period expired. Account deleted. Please sign up again.', timestamp: resendTime });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 10 * 60 * 1000;

    await db.execute({
      sql: 'INSERT OR REPLACE INTO user_otp_verification (email, otp, expires_at, created_at) VALUES (?, ?, ?, ?)',
      args: [email, otp, expiresAt, resendTime],
    });

    try {
      await sendOTP(email, otp);
      res.status(200).json({ success: true, message: 'OTP resent successfully. Please verify within 10 minutes.', timestamp: resendTime });
    } catch (emailErr) {
      console.warn('OTP generated, but email failed to send for', email);
      console.warn('OTP for testing (check database or resend):', otp);
      res.status(200).json({
        success: true,
        message: 'OTP generated, but email failed to send. OTP logged to console and stored in database. Please verify within 10 minutes.',
        timestamp: resendTime,
      });
    }
  } catch (err) {
    console.error('Resend OTP error at', resendTime, ':', err);
    res.status(500).json({ error: 'Failed to resend OTP: ' + err.message, timestamp: resendTime });
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

app.get('/progress', authenticateJWT, async (req, res) => {
  try {
    const db = getDB();
    const result = await db.execute({
      sql: 'SELECT * FROM user_module_progress WHERE user_id = ?',
      args: [req.user.id],
    });

    res.json({
      success: true,
      progress: result.rows
    });
  } catch (err) {
    console.error('Progress fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch progress' });
  }
});

// Get user profile
app.get('/profile', authenticateJWT, async (req, res) => {
  try {
    // Validate user ID
    if (!req.user.id) {
      return res.status(400).json({
        error: 'Invalid user ID',
        timestamp: getISTTimestamp()
      });
    }

    const db = getDB();
    const result = await db.execute({
      sql: 'SELECT user_id, username, email, is_google_auth, created_at, last_login, is_verified FROM user_profiles WHERE user_id = ?',
      args: [req.user.id]
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
      message: 'Profile fetched successfully',
      profile: {
        id: user.user_id,
        username: user.username,
        email: user.email,
        isGoogleAuth: user.is_google_auth,
        createdAt: user.created_at,
        lastLogin: user.last_login,
        isVerified: user.is_verified
      },
      timestamp: getISTTimestamp()
    });
  } catch (err) {
    console.error('Profile fetch error at', getISTTimestamp(), ':', err);
    res.status(500).json({
      error: 'Failed to fetch profile',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined,
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
  console.log('- Google Sign-In:', firebaseInitialized ? 'Enabled' : 'Disabled');
  console.log('- Indian Standard Time (IST) timestamps');
  console.log('- Bitmask progress tracking');
  console.log('- Email verification required:', REQUIRE_EMAIL_VERIFICATION);
  console.log('- Email service configured:', !!process.env.EMAIL_USER && !!process.env.EMAIL_PASS);
  console.log('- Auto-delete unverified users after 10 minutes');
});
