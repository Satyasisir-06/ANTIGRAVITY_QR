-- SUPABASE SCHEMA FOR QR ATTENDANCE (FULL V2.0)
-- Run this in the Supabase SQL Editor to set up the complete database

-- 1. Users Table (Updated for Roles)
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'student' -- 'admin', 'teacher', 'student'
);

-- 2. Master Student List
CREATE TABLE IF NOT EXISTS students (
    roll TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    branch TEXT NOT NULL,
    parent_email TEXT,
    parent_phone TEXT
);

-- 3. Teachers Table (NEW)
CREATE TABLE IF NOT EXISTS teachers (
    id SERIAL PRIMARY KEY,
    teacher_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    email TEXT,
    phone TEXT,
    user_id INTEGER REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 4. Teacher Subjects Assignment (NEW)
CREATE TABLE IF NOT EXISTS teacher_subjects (
    id SERIAL PRIMARY KEY,
    teacher_id INTEGER REFERENCES teachers(id),
    subject TEXT NOT NULL,
    branch TEXT NOT NULL,
    day_of_week TEXT,
    time_slot TEXT,
    semester TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(teacher_id, subject, branch, day_of_week, time_slot)
);

-- 5. Subjects Table (Generic List)
CREATE TABLE IF NOT EXISTS subjects (
    id SERIAL PRIMARY KEY,
    name TEXT UNIQUE NOT NULL
);

-- 6. Sessions Table (Updated with Teacher Tracking)
CREATE TABLE IF NOT EXISTS sessions (
    id SERIAL PRIMARY KEY,
    subject TEXT NOT NULL,
    branch TEXT NOT NULL,
    date TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    class_type TEXT NOT NULL,
    qr_token TEXT NOT NULL,
    is_finalized BOOLEAN DEFAULT FALSE,
    created_by INTEGER, -- User ID of creator (Admin/Teacher)
    teacher_id INTEGER, -- Link to teachers table (if created by teacher)
    start_timestamp INTEGER, -- Unix timestamp for accurate timers
    end_timestamp INTEGER    -- Unix timestamp for accurate timers
);

-- 7. Attendance Records
CREATE TABLE IF NOT EXISTS attendance (
    id SERIAL PRIMARY KEY,
    roll TEXT NOT NULL,
    name TEXT NOT NULL,
    subject TEXT NOT NULL,
    branch TEXT NOT NULL,
    date TEXT NOT NULL,
    time TEXT NOT NULL,
    ip_address TEXT,
    device_info TEXT,
    session_id INTEGER REFERENCES sessions(id),
    status TEXT DEFAULT 'PRESENT'
);

-- 8. Semester Config
CREATE TABLE IF NOT EXISTS semester_config (
    id SERIAL PRIMARY KEY,
    start_date TEXT,
    end_date TEXT,
    college_lat DOUBLE PRECISION,
    college_lng DOUBLE PRECISION,
    geo_enabled INTEGER DEFAULT 0,
    geo_radius INTEGER DEFAULT 200,
    sms_enabled INTEGER DEFAULT 0,
    sms_sid TEXT,
    sms_auth_token TEXT,
    sms_from_number TEXT,
    sms_threshold INTEGER DEFAULT 75
);

-- 9. SMS Logs
CREATE TABLE IF NOT EXISTS sms_logs (
    id SERIAL PRIMARY KEY,
    roll TEXT NOT NULL,
    session_id INTEGER,
    phone TEXT,
    message TEXT,
    status TEXT,
    error_message TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 10. Holidays
CREATE TABLE IF NOT EXISTS holidays (
    id SERIAL PRIMARY KEY,
    date TEXT UNIQUE NOT NULL,
    description TEXT
);

-- 11. Correction Requests
CREATE TABLE IF NOT EXISTS correction_requests (
    id SERIAL PRIMARY KEY,
    roll TEXT NOT NULL,
    session_id INTEGER,
    reason TEXT NOT NULL,
    proof_img TEXT,
    status TEXT DEFAULT 'PENDING',
    admin_comment TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_roll ON attendance(roll);
CREATE INDEX IF NOT EXISTS idx_date ON attendance(date);
CREATE INDEX IF NOT EXISTS idx_subject ON attendance(subject);
-- Ensure students can't mark twice for same subject on same date
CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_attendance ON attendance(roll, subject, date, branch);
