# QR Code Attendance System

A modern, secure, and eye-catching web application for managing student attendance via QR codes. Built with Python Flask and SQLite.

## 🎯 Project Overview
This project is designed to streamline the attendance process in educational institutions. Faculty (Admins) can generate unique, time-bounded QR codes for specific subjects and branches. Students mark their attendance by scanning these codes, ensuring a secure and efficient tracking system.

## ✨ Features
*   **Role-Based Access**: Separate dashboards for Admins (Faculty) and Students.
*   **Dynamic QR Generation**: QR codes include embedded expiry times (2 minutes validity) and session details.
*   **Secure Authentication**: Password hashing using `werkzeug.security`.
*   **Duplicate Prevention**: Prevents multiple entries for the same student/subject/session.
*   **Modern UI/UX**: Glassmorphism design, gradient backgrounds, and responsive layout.
*   **Export Data**: Admins can export attendance records to CSV.
*   **Live Dashboard**: Real-time view of attendance records with filters.

## 🛠 Technology Stack
*   **Backend**: Python (Flask)
*   **Database**: SQLite
*   **Frontend**: HTML5, CSS3 (Glassmorphism), JavaScript (AJAX)
*   **Deployment**: Vercel Ready

## 🗄️ Database Schema
**1. users**
*   `id`: Primary Key
*   `username`: Unique
*   `password`: Hashed
*   `role`: 'admin' or 'student'

**2. attendance**
*   `id`: Primary Key
*   `roll`: Student Roll Number
*   `name`: Student Name
*   `subject`: Subject Name
*   `branch`: Student Branch
*   `date`: Date of attendance
*   `time`: Time of marking

## 🚀 How to Run Locally

1.  **Clone the repository** (if applicable) or navigate to the project folder.
2.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```
3.  **Run the Application**:
    ```bash
    python app.py
    ```
4.  **Access the App**:
    Open your browser and navigate to `http://127.0.0.1:5000/`

## 🔐 Default Credentials
*   **Admin**:
    *   Username: `admin`
    *   Password: `admin123`
*   **Student**:
    *   Username: `student`
    *   Password: `student123`

## ☁️ Deployment (Vercel)
1.  Ensure `vercel.json` is present.
2.  Push to GitHub.
3.  Import project in Vercel.
4.  Deploy! (Note: SQLite persistence on Vercel is ephemeral; data resets on redeployment).

## 🔮 Future Enhancements
*   OTP-based login for extra security.
*   Face recognition integration.
*   Cloud database (PostgreSQL) for permanent serverless storage.
*   Mobile app wrapper.

---
**Viva Statement**: "This project implements a secure, QR-based attendance management system using Flask and SQLite with a modern UI, ensuring real-time attendance tracking and scalability."
