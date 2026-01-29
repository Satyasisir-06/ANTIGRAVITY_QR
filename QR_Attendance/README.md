# QR Code Attendance System

A modern, secure, and eye-catching web application for managing student attendance via QR codes. Built with **Go (Gin Framework)** and **Google Firestore**.

## 🎯 Project Overview
This project is designed to streamline the attendance process in educational institutions. Faculty (Admins) can generate unique, time-bounded QR codes for specific subjects and branches. Students mark their attendance by scanning these codes, ensuring a secure and efficient tracking system.

## ✨ Features
*   **Role-Based Access**: Separate dashboards for Admins (Faculty) and Students.
*   **Dynamic QR Generation**: QR codes include embedded expiry times (2 minutes validity) and session details.
*   **Secure Authentication**: Password hashing using `bcrypt`.
*   **Duplicate Prevention**: Prevents multiple entries for the same student/subject/session.
*   **Modern UI/UX**: Glassmorphism design, gradient backgrounds, and responsive layout.
*   **Live Dashboard**: Real-time view of attendance records.

## 🛠 Technology Stack
*   **Backend**: Go (Gin Gonic)
*   **Database**: Google Firestore
*   **Frontend**: HTML5, CSS3 (Glassmorphism), JavaScript
*   **Deployment**: Vercel Serverless (Go Runtime)

## 🚀 How to Run Locally

### Prerequisites
- [Go 1.21+](https://go.dev/dl/) installed.

### Steps
1.  **Clone the repository**.
2.  **Install Dependencies**:
    ```powershell
    go mod tidy
    ```
3.  **Run the Application**:
    ```powershell
    go run main.go
    ```
4.  **Access the App**:
    Open your browser and navigate to `http://localhost:8080`

## 🔐 Default Credentials
*   **Admin/Teacher**:
    *   Username: `admin` (or configured teacher ID)
    *   Password: `password` (check database or create new via code)
*   **Student**:
    *   Username: `student`
    *   Password: `student`

## ☁️ Deployment (Vercel)
1.  Push to GitHub.
2.  Import project in Vercel.
3.  Vercel will automatically detect `go.mod` and deploy using the Go runtime (configured in `vercel.json`).

---
**Viva Statement**: "This project implements a secure, QR-based attendance management system using Go and Firestore with a modern UI, ensuring real-time attendance tracking and scalability."
