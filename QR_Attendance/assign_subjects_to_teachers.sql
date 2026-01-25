-- ================================================
-- ASSIGN SUBJECTS TO YOUR TEACHERS IN SUPABASE
-- ================================================

-- This SQL will assign subjects to CEC25865
-- Copy this to Supabase SQL Editor and modify as needed

-- First, find the teacher's database ID
-- (Replace 'CEC25865' with your teacher_id)
SELECT id, teacher_id, name FROM teachers WHERE teacher_id = 'CEC25865';

-- Let's say the ID returned is 5
-- Now assign subjects (replace 5 with the actual ID from above)

INSERT INTO teacher_subjects (teacher_id, subject, branch, day_of_week, time_slot, semester)
VALUES 
(5, 'Data Structures', 'CSM', 'Monday', '09:00-10:00', '2025-Spring'),
(5, 'Java Programming', 'CSM', 'Tuesday', '11:00-12:00', '2025-Spring'),
(5, 'Database Systems', 'CSM', 'Wednesday', '14:00-15:00', '2025-Spring');

-- Repeat for other teachers:
-- CEC25667:
-- SELECT id FROM teachers WHERE teacher_id = 'CEC25667';
-- INSERT INTO teacher_subjects (teacher_id, subject, branch, day_of_week, time_slot, semester)
-- VALUES 
-- (6, 'Web Development', 'CSE-A', 'Monday', '10:00-11:00', '2025-Spring');

-- Satya2356:
-- SELECT id FROM teachers WHERE teacher_id = 'Satya2356';
-- INSERT INTO teacher_subjects (teacher_id, subject, branch, day_of_week, time_slot, semester)
-- VALUES 
-- (7, 'Python Programming', 'CSE-B', 'Friday', '09:00-10:00', '2025-Spring');

-- Verify it worked:
SELECT 
    t.teacher_id,
    t.name,
    ts.subject,
    ts.branch,
    ts.day_of_week,
    ts.time_slot
FROM teachers t
LEFT JOIN teacher_subjects ts ON t.id = ts.teacher_id
WHERE t.teacher_id IN ('CEC25865', 'CEC25667', 'Satya2356', 'S2856');
