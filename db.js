import { createClient } from '@libsql/client';
import dotenv from 'dotenv';

dotenv.config();

const db = createClient({
  url: process.env.DATABASE_URL,
  authToken: process.env.DATABASE_AUTH_TOKEN,
});

export async function initDB() {
  try {
    await db.batch([
      {
        sql: `
          CREATE TABLE IF NOT EXISTS user_profiles (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL UNIQUE,
            password_hash VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP DEFAULT CURRENT_TIMESTAMP
          )
        `,
      },
      {
        sql: `
          CREATE TABLE IF NOT EXISTS user_module_progress (
            user_id INTEGER,
            language VARCHAR(50),
            level INTEGER,
            module_id INTEGER,
            completion_mask BIGINT DEFAULT 0,
            current_lesson_id INTEGER DEFAULT 1,
            current_question_index INTEGER DEFAULT 0,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (user_id, language, level, module_id),
            FOREIGN KEY (user_id) REFERENCES user_profiles(user_id) ON DELETE CASCADE
          )
        `,
      },
      {
        sql: `
          CREATE TABLE IF NOT EXISTS user_achievements (
            user_id INTEGER PRIMARY KEY,
            xp_points INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES user_profiles(user_id) ON DELETE CASCADE
          )
        `,
      },
      {
        sql: `
          CREATE TABLE IF NOT EXISTS lesson_details (
            language VARCHAR(50),
            level INTEGER,
            module_id INTEGER,
            total_lessons INTEGER,
            PRIMARY KEY (language, level, module_id)
          )
        `,
      }
    ]);
    console.log('Database tables created successfully');
  } catch (err) {
    console.error('Failed to create database tables:', err);
    throw err;
  }
}

export function getDB() {
  return db;
}