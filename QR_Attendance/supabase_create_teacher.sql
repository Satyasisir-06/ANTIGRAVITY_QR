-- ================================================
-- SUPABASE SQL TO FIX TEACHER LOGIN
-- Copy and paste this ENTIRE block into Supabase SQL Editor
-- ================================================

-- First, let's clean up any duplicate or broken accounts
DELETE FROM teachers WHERE teacher_id = 'CEC25867';
DELETE FROM users WHERE username = 'CEC25867';

-- Now create the account with the CORRECT password hash
-- This hash is for password: sisir@2009
INSERT INTO users (username, password, role)
VALUES (
    'CEC25867',
    'scrypt:32768:8:1$PJvqtDbbwjlsrxn8$d8f514184deb7e629f80f8810e261af58ea91acdf6821250c21daf137b05883236d95eb1',
    'teacher'
);

-- Create the teacher profile linked to this user
INSERT INTO teachers (teacher_id, name, email, phone, user_id)
VALUES (
    'CEC25867',
    'Teacher CEC25867', 
    'cec25867@college.edu',
    NULL,
    (SELECT id FROM users WHERE username = 'CEC25867')
);

-- Verify it worked
SELECT 
    u.id as user_id,
    u.username,
    u.role,
    t.id as teacher_id,
    t.name,
    t.email
FROM users u
LEFT JOIN teachers t ON u.id = t.user_id
WHERE u.username = 'CEC25867';
