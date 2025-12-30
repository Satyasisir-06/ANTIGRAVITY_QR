-- SUPABASE SCHEMA FOR QR ATTENDANCE
-- Run this in the Supabase SQL Editor

-- 1. Users Table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL
);

-- 2. Master Student List
CREATE TABLE IF NOT EXISTS students (
    roll TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    branch TEXT NOT NULL,
    parent_email TEXT,
    parent_phone TEXT
);

-- 3. Subjects Table
CREATE TABLE IF NOT EXISTS subjects (
    id SERIAL PRIMARY KEY,
    name TEXT UNIQUE NOT NULL
);

-- 4. Sessions Table
CREATE TABLE IF NOT EXISTS sessions (
    id SERIAL PRIMARY KEY,
    subject TEXT NOT NULL,
    branch TEXT NOT NULL,
    date TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    class_type TEXT NOT NULL,
    qr_token TEXT NOT NULL,
    is_finalized BOOLEAN DEFAULT FALSE
);

-- 5. Attendance Records
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
    session_id INTEGER,
    status TEXT DEFAULT 'PRESENT'
);

-- 6. Semester Config
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

-- 7. SMS Logs
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

-- 8. Holidays
CREATE TABLE IF NOT EXISTS holidays (
    id SERIAL PRIMARY KEY,
    date TEXT UNIQUE NOT NULL,
    description TEXT
);

-- 9. Correction Requests
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
CREATE INDEX idx_roll ON attendance(roll);
CREATE INDEX idx_date ON attendance(date);
CREATE INDEX idx_subject ON attendance(subject);
CREATE UNIQUE INDEX idx_unique_attendance ON attendance(roll, subject, date);

-- Default Admin User (Password will be updated by app initialization)
-- Note: The app will automatically insert admin123 if table is empty
