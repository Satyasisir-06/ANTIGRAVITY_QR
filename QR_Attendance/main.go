package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"image"
	"image/draw"
	"image/png"
	"log"
	"math"
	"net/http"
	"net/smtp"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/firestore"
	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

func init() {
	// Force timezone to Asia/Kolkata
	loc, err := time.LoadLocation("Asia/Kolkata")
	if err != nil {
		// Fallback for Windows if tzdata is missing
		log.Printf("Warning: Could not load Asia/Kolkata location: %v. Using FixedZone.", err)
		loc = time.FixedZone("IST", 5*3600+30*60) // UTC+5:30
	}
	time.Local = loc
	log.Println("Global timezone set to:", time.Local)
}

// ==================== RATE LIMITER ====================

type RateLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	limit    int
	window   time.Duration
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		attempts: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
	// Cleanup goroutine
	go func() {
		for {
			time.Sleep(window)
			rl.cleanup()
		}
	}()
	return rl
}

func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	for key, times := range rl.attempts {
		var valid []time.Time
		for _, t := range times {
			if now.Sub(t) < rl.window {
				valid = append(valid, t)
			}
		}
		if len(valid) == 0 {
			delete(rl.attempts, key)
		} else {
			rl.attempts[key] = valid
		}
	}
}

func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()

	// Filter out old attempts
	var valid []time.Time
	for _, t := range rl.attempts[key] {
		if now.Sub(t) < rl.window {
			valid = append(valid, t)
		}
	}

	if len(valid) >= rl.limit {
		rl.attempts[key] = valid
		return false
	}

	rl.attempts[key] = append(valid, now)
	return true
}

// Global rate limiters
var (
	loginLimiter    = NewRateLimiter(5, time.Minute)   // 5 attempts per minute
	registerLimiter = NewRateLimiter(3, time.Minute*5) // 3 attempts per 5 minutes
	apiLimiter      = NewRateLimiter(60, time.Minute)  // 60 API calls per minute
)

// CSRF Token generation
func generateCSRFToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// Haversine formula for distance calculation (geofencing)
func haversineDistance(lat1, lon1, lat2, lon2 float64) float64 {
	const R = 6371000 // Earth's radius in meters

	lat1Rad := lat1 * math.Pi / 180
	lat2Rad := lat2 * math.Pi / 180
	deltaLat := (lat2 - lat1) * math.Pi / 180
	deltaLon := (lon2 - lon1) * math.Pi / 180

	a := math.Sin(deltaLat/2)*math.Sin(deltaLat/2) +
		math.Cos(lat1Rad)*math.Cos(lat2Rad)*
			math.Sin(deltaLon/2)*math.Sin(deltaLon/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))

	return R * c // Distance in meters
}

// ==================== MODELS ====================

type User struct {
	ID        string    `json:"id" firestore:"id,omitempty"`
	Username  string    `json:"username" firestore:"username"`
	Password  string    `json:"password" firestore:"password"`
	Role      string    `json:"role" firestore:"role"`
	Email     string    `json:"email" firestore:"email"`
	CreatedAt time.Time `json:"created_at" firestore:"created_at"`
}

type Session struct {
	ID             string  `json:"id" firestore:"id,omitempty"`
	TeacherID      string  `json:"teacher_id" firestore:"teacher_id"`
	TeacherName    string  `json:"teacher_name" firestore:"teacher_name"` // Added for display
	Subject        string  `json:"subject" firestore:"subject"`
	Branch         string  `json:"branch" firestore:"branch"`
	ClassType      string  `json:"class_type" firestore:"class_type"`
	StartTime      float64 `json:"start_time" firestore:"start_time"`
	EndTime        float64 `json:"end_time" firestore:"end_time"`
	IsFinalized    bool    `json:"is_finalized" firestore:"is_finalized"`
	QRToken        string  `json:"qr_token" firestore:"qr_token"`
	Date           string  `json:"date" firestore:"date"`
	Time           string  `json:"time" firestore:"time"`
	StartTimestamp float64 `json:"start_timestamp" firestore:"start_timestamp,omitempty"`
}

type Attendance struct {
	ID        string    `json:"id" firestore:"id,omitempty"`
	SessionID string    `json:"session_id" firestore:"session_id"`
	Roll      string    `json:"roll" firestore:"roll"`
	Name      string    `json:"name" firestore:"name"` // Added for display
	Status    string    `json:"status" firestore:"status"`
	Subject   string    `json:"subject,omitempty" firestore:"subject,omitempty"`
	Branch    string    `json:"branch,omitempty" firestore:"branch,omitempty"`
	Date      string    `json:"date,omitempty" firestore:"date,omitempty"`
	Time      string    `json:"time,omitempty" firestore:"time,omitempty"`
	TeacherID string    `json:"teacher_id,omitempty" firestore:"teacher_id,omitempty"`
	Timestamp time.Time `json:"timestamp" firestore:"timestamp"`
}

type SemesterConfig struct {
	StartDate     string  `json:"start_date" firestore:"start_date"`
	EndDate       string  `json:"end_date" firestore:"end_date"`
	GeoEnabled    bool    `json:"geo_enabled" firestore:"geo_enabled"`
	CollegeLat    float64 `json:"college_lat" firestore:"college_lat"`
	CollegeLng    float64 `json:"college_lng" firestore:"college_lng"`
	GeoRadius     float64 `json:"geo_radius" firestore:"geo_radius"`
	SMSEnabled    bool    `json:"sms_enabled" firestore:"sms_enabled"`
	SMSSID        string  `json:"sms_sid" firestore:"sms_sid"`
	SMSAuthToken  string  `json:"sms_auth_token" firestore:"sms_auth_token"`
	SMSFromNumber string  `json:"sms_from_number" firestore:"sms_from_number"`
	SMSThreshold  int     `json:"sms_threshold" firestore:"sms_threshold"`
	// Email Configuration (Backup for SMS)
	EmailEnabled  bool   `json:"email_enabled" firestore:"email_enabled"`
	SMTPServer    string `json:"smtp_server" firestore:"smtp_server"`
	SMTPPort      int    `json:"smtp_port" firestore:"smtp_port"`
	EmailFrom     string `json:"email_from" firestore:"email_from"`
	EmailPassword string `json:"email_password" firestore:"email_password"`
}

type Holiday struct {
	ID          string `json:"id" firestore:"id,omitempty"`
	Date        string `json:"date" firestore:"date"`
	Description string `json:"description" firestore:"description"`
	DateDisplay string `json:"date_display" firestore:"-"` // Helper
}

type Subject struct {
	ID        string `json:"id" firestore:"id,omitempty"`
	TeacherID string `json:"teacher_id" firestore:"teacher_id"`
	Name      string `json:"name" firestore:"name"`       // Used as Subject field
	Subject   string `json:"subject" firestore:"subject"` // Alias for template
	Branch    string `json:"branch" firestore:"branch"`
	DayOfWeek string `json:"day_of_week" firestore:"day_of_week"`
	TimeSlot  string `json:"time_slot" firestore:"time_slot"`
}

type Student struct {
	Roll        string `json:"roll" firestore:"roll"`
	Name        string `json:"name" firestore:"name"`
	Branch      string `json:"branch" firestore:"branch"`
	ParentPhone string `json:"parent_phone" firestore:"parent_phone"`
}

type SMSLog struct {
	Timestamp    string `json:"timestamp"`
	Roll         string `json:"roll"`
	Phone        string `json:"phone"`
	Message      string `json:"message"`
	Status       string `json:"status"`
	ErrorMessage string `json:"error_message"`
}

type CorrectionRequest struct {
	ID             string    `json:"id" firestore:"id,omitempty"`
	StudentID      string    `json:"student_id" firestore:"student_id"`
	StudentName    string    `json:"student_name" firestore:"student_name"`
	Roll           string    `json:"roll" firestore:"roll"`
	Branch         string    `json:"branch" firestore:"branch"`
	Subject        string    `json:"subject" firestore:"subject"`
	TeacherID      string    `json:"teacher_id" firestore:"teacher_id"`
	TeacherName    string    `json:"teacher_name" firestore:"teacher_name"`
	AbsentDate     string    `json:"absent_date" firestore:"absent_date"`
	Reason         string    `json:"reason" firestore:"reason"`
	ProofImg       string    `json:"proof_img" firestore:"proof_img"`
	Status         string    `json:"status" firestore:"status"` // PENDING, APPROVED, REJECTED
	TeacherRemarks string    `json:"teacher_remarks" firestore:"teacher_remarks"`
	CreatedAt      time.Time `json:"created_at" firestore:"created_at"`
	UpdatedAt      time.Time `json:"updated_at" firestore:"updated_at"`
}

type TeacherAttendance struct {
	ID        string    `json:"id" firestore:"id,omitempty"`
	TeacherID string    `json:"teacher_id" firestore:"teacher_id"`
	Name      string    `json:"name" firestore:"name"`
	Date      string    `json:"date" firestore:"date"`
	Time      string    `json:"time" firestore:"time"`
	Status    string    `json:"status" firestore:"status"` // PRESENT, ABSENT
	Timestamp time.Time `json:"timestamp" firestore:"timestamp"`
}

type TeacherIssue struct {
	ID           string    `json:"id" firestore:"id,omitempty"`
	TeacherID    string    `json:"teacher_id" firestore:"teacher_id"`
	Name         string    `json:"name" firestore:"name"`
	Date         string    `json:"date" firestore:"date"` // The date the issue is about
	Reason       string    `json:"reason" firestore:"reason"`
	ProofURL     string    `json:"proof_url" firestore:"proof_url"`
	Status       string    `json:"status" firestore:"status"` // PENDING, APPROVED, REJECTED
	AdminRemarks string    `json:"admin_remarks" firestore:"admin_remarks"`
	CreatedAt    time.Time `json:"created_at" firestore:"created_at"`
}

// PermissionRequest represents a teacher's leave/permission request
type PermissionRequest struct {
	ID           string    `json:"id" firestore:"id,omitempty"`
	TeacherID    string    `json:"teacher_id" firestore:"teacher_id"`
	TeacherName  string    `json:"teacher_name" firestore:"teacher_name"`
	Title        string    `json:"title" firestore:"title"`
	StartDate    string    `json:"start_date" firestore:"start_date"`
	EndDate      string    `json:"end_date" firestore:"end_date"`
	TimeFrom     string    `json:"time_from" firestore:"time_from"`
	TimeTo       string    `json:"time_to" firestore:"time_to"`
	Reason       string    `json:"reason" firestore:"reason"`
	Status       string    `json:"status" firestore:"status"` // PENDING, APPROVED, REJECTED
	AdminRemarks string    `json:"admin_remarks" firestore:"admin_remarks"`
	CreatedAt    time.Time `json:"created_at" firestore:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" firestore:"updated_at"`
}

// PendingTeacherRegistration represents a teacher registration awaiting admin approval
type PendingTeacherRegistration struct {
	ID           string    `json:"id" firestore:"id,omitempty"`
	TeacherID    string    `json:"teacher_id" firestore:"teacher_id"`
	FullName     string    `json:"full_name" firestore:"full_name"`
	Email        string    `json:"email" firestore:"email"`
	Phone        string    `json:"phone" firestore:"phone"`
	Password     string    `json:"password" firestore:"password"` // Hashed
	Status       string    `json:"status" firestore:"status"`     // PENDING, APPROVED, REJECTED
	CreatedAt    time.Time `json:"created_at" firestore:"created_at"`
	ReviewedAt   time.Time `json:"reviewed_at" firestore:"reviewed_at,omitempty"`
	AdminRemarks string    `json:"admin_remarks" firestore:"admin_remarks,omitempty"`
}

// ==================== GLOBAL CLIENTS ====================

var firestoreClient *firestore.Client
var authClient *auth.Client
var app *firebase.App

func initFirebase() {
	ctx := context.Background()
	credsPath := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	if credsPath == "" {
		if _, err := os.Stat("firebase-credentials.json"); err == nil {
			credsPath = "firebase-credentials.json"
		} else if _, err := os.Stat("QR_Attendance/firebase-credentials.json"); err == nil {
			credsPath = "QR_Attendance/firebase-credentials.json"
		}
	}

	var opts []option.ClientOption
	if credsPath != "" {
		fmt.Println("[FIREBASE] Using credentials from:", credsPath)
		opts = append(opts, option.WithCredentialsFile(credsPath))
	} else {
		if config := os.Getenv("FIREBASE_CONFIG"); config != "" {
			opts = append(opts, option.WithCredentialsJSON([]byte(config)))
		} else {
			fmt.Println("[FIREBASE] WARNING: No explicit credentials found, trying default.")
		}
	}

	var err error
	app, err = firebase.NewApp(ctx, nil, opts...)
	if err != nil {
		log.Fatalf("error initializing app: %v\n", err)
	}

	firestoreClient, err = app.Firestore(ctx)
	if err != nil {
		log.Fatalf("error initializing firestore: %v\n", err)
	}
	authClient, err = app.Auth(ctx)
	if err != nil {
		log.Printf("error initializing auth client (optional): %v\n", err)
	}
	fmt.Println("[FIREBASE] Initialized successfully")
}

// ==================== HELPERS ====================

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func getStudentName(roll string) string {
	// Simple cache or direct fetch could be better, for now direct
	doc, err := firestoreClient.Collection("students").Doc(roll).Get(context.Background())
	if err == nil && doc.Exists() {
		return fmt.Sprint(doc.Data()["name"])
	}
	return roll
}

func getConfig() SemesterConfig {
	doc, err := firestoreClient.Collection("config").Doc("main").Get(context.Background())
	var config SemesterConfig
	if err == nil && doc.Exists() {
		doc.DataTo(&config)
	}
	return config
}

// ==================== HANDLERS ====================

func loginHandler(c *gin.Context) {
	if c.Request.Method == "GET" {
		// Generate CSRF token for form
		csrfToken := generateCSRFToken()
		session := sessions.Default(c)
		session.Set("csrf_token", csrfToken)
		session.Save()
		c.HTML(http.StatusOK, "login.html", gin.H{"csrf_token": csrfToken})
		return
	}

	// Rate limiting check
	clientIP := c.ClientIP()
	if !loginLimiter.Allow(clientIP) {
		c.HTML(http.StatusTooManyRequests, "login.html", gin.H{"error": "Too many login attempts. Please wait a minute and try again."})
		return
	}

	username := c.PostForm("username")
	password := c.PostForm("password")

	doc, err := firestoreClient.Collection("users").Doc(username).Get(context.Background())
	if err != nil || !doc.Exists() {
		c.HTML(http.StatusOK, "login.html", gin.H{"error": "Invalid username or password"})
		return
	}
	var user User
	if err := doc.DataTo(&user); err != nil {
		c.HTML(http.StatusOK, "login.html", gin.H{"error": "System error"})
		return
	}
	log.Printf("[LOGIN] Found user: %s, Role from DB: '%s'", user.Username, user.Role)
	if !checkPasswordHash(password, user.Password) {
		c.HTML(http.StatusOK, "login.html", gin.H{"error": "Invalid username or password"})
		return
	}

	session := sessions.Default(c)
	session.Set("user_id", user.Username)
	session.Set("username", user.Username)
	session.Set("role", user.Role)
	err = session.Save()
	if err != nil {
		log.Printf("[LOGIN] Error saving session: %v", err)
	}
	log.Printf("[LOGIN] User %s logged in with role: %s", user.Username, user.Role)

	if user.Role == "admin" {
		c.Redirect(http.StatusFound, "/admin")
	} else if user.Role == "teacher" {
		c.Redirect(http.StatusFound, "/teacher")
	} else {
		c.Redirect(http.StatusFound, "/student")
	}
}

func registerHandler(c *gin.Context) {
	if c.Request.Method == "GET" {
		csrfToken := generateCSRFToken()
		session := sessions.Default(c)
		session.Set("csrf_token", csrfToken)
		session.Save()
		c.HTML(http.StatusOK, "register.html", gin.H{"csrf_token": csrfToken})
		return
	}

	// Rate limiting check
	clientIP := c.ClientIP()
	if !registerLimiter.Allow(clientIP) {
		c.HTML(http.StatusTooManyRequests, "register.html", gin.H{"error": "Too many registration attempts. Please wait 5 minutes and try again."})
		return
	}

	username := c.PostForm("username")
	password := c.PostForm("password")
	role := c.PostForm("role")
	email := c.PostForm("email") // Teacher email

	// Student specific fields
	studentName := c.PostForm("student_name")
	studentEmail := c.PostForm("student_email")
	studentBranch := c.PostForm("student_branch")

	// Check if user already exists in users collection
	_, err := firestoreClient.Collection("users").Doc(username).Get(context.Background())
	if err == nil {
		c.HTML(http.StatusOK, "register.html", gin.H{"error": "User already exists"})
		return
	}

	// For teachers, also check if they have a pending registration
	if role == "teacher" {
		// Check pending_teacher_registrations for existing pending request
		iter := firestoreClient.Collection("pending_teacher_registrations").Where("teacher_id", "==", username).Documents(context.Background())
		doc, err := iter.Next()
		if err == nil && doc.Exists() {
			var pending PendingTeacherRegistration
			doc.DataTo(&pending)
			if pending.Status == "PENDING" {
				c.HTML(http.StatusOK, "register.html", gin.H{"error": "You already have a pending registration. Please wait for admin approval."})
				return
			} else if pending.Status == "REJECTED" {
				c.HTML(http.StatusOK, "register.html", gin.H{"error": "Your previous registration was rejected. Please contact the admin."})
				return
			}
		}

		// Create pending teacher registration
		fullName := c.PostForm("full_name")
		phone := c.PostForm("phone")
		hashed, _ := hashPassword(password)

		pendingReg := PendingTeacherRegistration{
			TeacherID: username,
			FullName:  fullName,
			Email:     email,
			Phone:     phone,
			Password:  hashed,
			Status:    "PENDING",
			CreatedAt: time.Now(),
		}

		_, _, err = firestoreClient.Collection("pending_teacher_registrations").Add(context.Background(), pendingReg)
		if err != nil {
			c.HTML(http.StatusOK, "register.html", gin.H{"error": "Failed to submit registration: " + err.Error()})
			return
		}

		log.Printf("[REGISTER] Teacher registration submitted for approval: %s (%s)", username, fullName)
		c.HTML(http.StatusOK, "registration_pending.html", gin.H{
			"teacher_id": username,
			"full_name":  fullName,
		})
		return
	}

	// For students, register directly (existing behavior)
	hashed, _ := hashPassword(password)
	userEmail := studentEmail

	user := User{Username: username, Password: hashed, Role: role, Email: userEmail, CreatedAt: time.Now()}
	_, err = firestoreClient.Collection("users").Doc(username).Set(context.Background(), user)
	if err != nil {
		c.HTML(http.StatusOK, "register.html", gin.H{"error": err.Error()})
		return
	}

	// Create student entry
	studentData := map[string]interface{}{
		"roll":       username,
		"name":       studentName,
		"email":      studentEmail,
		"branch":     studentBranch,
		"created_at": time.Now(),
	}
	_, err = firestoreClient.Collection("students").Doc(username).Set(context.Background(), studentData)
	if err != nil {
		log.Printf("Error creating student record: %v", err)
	}

	c.Redirect(http.StatusFound, "/login")
}

func teacherDashboard(c *gin.Context) {
	session := sessions.Default(c)
	userID := session.Get("user_id")
	role := session.Get("role")
	log.Printf("[TEACHER] Session check - userID: %v, role: %v", userID, role)
	if userID == nil || role != "teacher" {
		log.Printf("[TEACHER] Access denied - redirecting to login")
		c.Redirect(http.StatusFound, "/login")
		return
	}
	teacherID := userID.(string)

	// Get Teacher
	doc, _ := firestoreClient.Collection("teachers").Doc(teacherID).Get(context.Background())
	teacherName := teacherID
	email := ""
	phone := ""
	department := ""
	profilePic := ""
	if doc.Exists() {
		if v := doc.Data()["name"]; v != nil {
			teacherName = fmt.Sprint(v)
		}
		if v := doc.Data()["email"]; v != nil {
			email = fmt.Sprint(v)
		}
		if v := doc.Data()["phone"]; v != nil {
			phone = fmt.Sprint(v)
		}
		if v := doc.Data()["department"]; v != nil {
			department = fmt.Sprint(v)
		}
		if v := doc.Data()["profile_pic"]; v != nil {
			profilePic = fmt.Sprint(v)
		}
	}

	// Get Subjects
	subjects := []Subject{}
	iter := firestoreClient.Collection("subjects").Where("teacher_id", "==", teacherID).Documents(context.Background())
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Printf("[TEACHER] Error fetching subject: %v", err)
			break
		}
		var s Subject
		doc.DataTo(&s)
		s.ID = doc.Ref.ID
		s.Subject = s.Name
		subjects = append(subjects, s)
	}

	// Active Sessions - Auto-finalize expired ones
	activeSessions := []Session{}
	now := time.Now()
	// NOTE: Removed .Where("teacher_id", "==", teacherID) to avoid composite index requirement
	sessIter := firestoreClient.Collection("sessions").Where("is_finalized", "==", false).Documents(context.Background())
	for {
		doc, err := sessIter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Printf("[TEACHER] Error fetching session: %v", err)
			break
		}
		var s Session
		doc.DataTo(&s)
		s.ID = doc.Ref.ID

		// Filter for this teacher
		if s.TeacherID != teacherID {
			continue
		}
		doc.DataTo(&s)
		s.ID = doc.Ref.ID

		// Check if session has expired (EndTime has passed)
		endTimeUnix := int64(s.EndTime)
		if endTimeUnix > 0 && now.Unix() > endTimeUnix {
			// Auto-finalize this expired session
			firestoreClient.Collection("sessions").Doc(s.ID).Update(context.Background(), []firestore.Update{
				{Path: "is_finalized", Value: true},
			})
			log.Printf("[AUTO-EXPIRE] Session %s for %s has been auto-finalized (class time ended)", s.ID, s.Subject)
			continue // Don't add to active sessions
		}

		activeSessions = append(activeSessions, s)
	}

	c.HTML(http.StatusOK, "teacher_simple.html", gin.H{
		"teacher": gin.H{
			"Name":       teacherName,
			"TeacherID":  teacherID,
			"Email":      email,
			"Phone":      phone,
			"Department": department,
			"ProfilePic": profilePic,
		},
		"all_subjects":    subjects,
		"today_subjects":  subjects, // Mock: filter by day in real app
		"active_sessions": activeSessions,
	})
}

func startSessionHandler(c *gin.Context) {
	subject := c.PostForm("subject")
	classType := c.PostForm("class_type")
	session := sessions.Default(c)
	teacherID := session.Get("user_id").(string)

	// Fetch branch from subject
	// Ideally we query subject collection. For now, assume it's passed or lookup
	branch := "Unknown"
	// Simple lookup in subjects
	iter := firestoreClient.Collection("subjects").Where("teacher_id", "==", teacherID).Where("name", "==", subject).Documents(context.Background())
	doc, err := iter.Next()
	if err == nil {
		branch = fmt.Sprint(doc.Data()["branch"])
	}

	now := time.Now()
	duration := 1.0
	if classType == "Lab" {
		duration = 3.0
	}
	endTime := now.Add(time.Duration(duration) * time.Hour)
	qrToken := fmt.Sprintf("%d-%s", now.UnixNano(), teacherID)

	newSession := Session{
		TeacherID:   teacherID,
		TeacherName: teacherID, // Update to real name if needed
		Subject:     subject,
		Branch:      branch, // Found from subject
		ClassType:   classType,
		StartTime:   float64(now.Unix()),
		EndTime:     float64(endTime.Unix()),
		IsFinalized: false,
		QRToken:     qrToken,
		Date:        now.Format("2006-01-02"),
		Time:        now.Format("15:04:05"),
	}
	ref, _, err := firestoreClient.Collection("sessions").Add(context.Background(), newSession)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": err.Error()})
		return
	}
	// Redirect to QR display page so teacher can show QR to students
	c.Redirect(http.StatusFound, "/qr_display?token="+qrToken)
	_ = ref // suppress unused
}

func finalizeSessionHandler(c *gin.Context) {
	sessionID := c.PostForm("session_id")
	_, err := firestoreClient.Collection("sessions").Doc(sessionID).Update(context.Background(), []firestore.Update{
		{Path: "is_finalized", Value: true},
	})
	if err != nil {
		fmt.Println("Error finalizing:", err)
	}
	c.Redirect(http.StatusFound, "/teacher")
}

func addSubjectHandler(c *gin.Context) {
	session := sessions.Default(c)
	teacherID := session.Get("user_id").(string)

	s := Subject{
		TeacherID: teacherID,
		Name:      c.PostForm("subject"),
		Branch:    c.PostForm("branch"),
		DayOfWeek: c.PostForm("day_of_week"),
		TimeSlot:  c.PostForm("time_slot"),
	}
	firestoreClient.Collection("subjects").Add(context.Background(), s)
	c.Redirect(http.StatusFound, "/teacher")
}

func deleteSubjectHandler(c *gin.Context) {
	id := c.PostForm("subject_id")
	firestoreClient.Collection("subjects").Doc(id).Delete(context.Background())
	c.Redirect(http.StatusFound, "/teacher")
}

func studentDashboard(c *gin.Context) {
	session := sessions.Default(c)
	userID := session.Get("user_id")
	if userID == nil {
		c.Redirect(http.StatusFound, "/login")
		return
	}
	if session.Get("role") != "student" {
		c.Redirect(http.StatusFound, "/login")
		return
	}
	studentID, ok := userID.(string)
	if !ok {
		log.Println("Error: userID is not a string", userID)
		c.String(http.StatusInternalServerError, "Session error: userID invalid")
		return
	}

	log.Println("Student Dashboard access for:", studentID)

	// Fetch Student Details
	doc, err := firestoreClient.Collection("students").Doc(studentID).Get(context.Background())
	studentName := studentID
	branch := ""
	studentEmail := ""
	if err != nil {
		log.Printf("Error fetching student doc for %s: %v", studentID, err)
	} else if doc.Exists() {
		if v := doc.Data()["name"]; v != nil {
			studentName = fmt.Sprint(v)
		}
		if v := doc.Data()["branch"]; v != nil {
			branch = fmt.Sprint(v)
		}
		if v := doc.Data()["email"]; v != nil {
			studentEmail = fmt.Sprint(v)
		}
	} else {
		log.Println("Student doc does not exist for:", studentID)
	}

	// Fetch semester config from admin settings
	config := getConfig()

	// Calculate semester dates
	now := time.Now()
	var semesterStart, semesterEnd time.Time
	remainingSemDays := 0
	workingDays := 0

	if config.StartDate != "" {
		semesterStart, _ = time.Parse("2006-01-02", config.StartDate)
	}
	if config.EndDate != "" {
		semesterEnd, _ = time.Parse("2006-01-02", config.EndDate)
	}

	// Fetch holidays for working days calculation
	holidays := make(map[string]bool)
	holidayIter := firestoreClient.Collection("holidays").Documents(context.Background())
	for {
		hDoc, err := holidayIter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			break
		}
		var h Holiday
		hDoc.DataTo(&h)
		holidays[h.Date] = true
	}

	// Calculate remaining semester days (excluding weekends and holidays)
	if !semesterEnd.IsZero() && now.Before(semesterEnd) {
		for d := now; !d.After(semesterEnd); d = d.AddDate(0, 0, 1) {
			dateStr := d.Format("2006-01-02")
			// Skip weekends (Saturday=6, Sunday=0)
			if d.Weekday() == time.Sunday || d.Weekday() == time.Saturday {
				continue
			}
			// Skip holidays
			if holidays[dateStr] {
				continue
			}
			remainingSemDays++
		}
	}

	// Calculate total working days from semester start to today
	if !semesterStart.IsZero() {
		endCalc := now
		if !semesterEnd.IsZero() && now.After(semesterEnd) {
			endCalc = semesterEnd
		}
		for d := semesterStart; !d.After(endCalc); d = d.AddDate(0, 0, 1) {
			dateStr := d.Format("2006-01-02")
			if d.Weekday() == time.Sunday || d.Weekday() == time.Saturday {
				continue
			}
			if holidays[dateStr] {
				continue
			}
			workingDays++
		}
	}

	// Fetch all attendance records for this student
	records := []Attendance{}
	totalPresent := 0

	// Query without OrderBy to avoid composite index requirement
	iter := firestoreClient.Collection("attendance").Where("roll", "==", studentID).Documents(context.Background())
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Println("Error iterating attendance for student", studentID, ":", err)
			break
		}
		var a Attendance
		doc.DataTo(&a)
		a.ID = doc.Ref.ID

		// Log for debugging
		log.Printf("Found attendance record for %s: Subject=%s, Date=%s, Status=%s", studentID, a.Subject, a.Date, a.Status)

		records = append(records, a)
		if a.Status == "PRESENT" {
			totalPresent++
		}
	}

	log.Printf("Total records found for student %s: %d, Present: %d", studentID, len(records), totalPresent)

	// Calculate percentage
	var percentage float64 = 0.0
	if workingDays > 0 {
		percentage = (float64(totalPresent) / float64(workingDays)) * 100
	}

	log.Println("Rendering student.html for:", studentName)

	c.HTML(http.StatusOK, "student.html", gin.H{
		"username":           studentName,
		"student_name":       studentName,
		"student_id":         studentID,
		"branch":             branch,
		"email":              studentEmail,
		"total_present":      totalPresent,
		"working_days":       workingDays,
		"remaining_sem_days": remainingSemDays,
		"percentage":         percentage,
		"records":            records,
		"semester_start":     config.StartDate,
		"semester_end":       config.EndDate,
	})
}

func adminDashboard(c *gin.Context) {
	session := sessions.Default(c)
	if session.Get("role") != "admin" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	// Fetch Counts from actual student registrations
	cseCount := 0
	aiCount := 0
	eceCount := 0
	eeeCount := 0
	mechCount := 0
	civilCount := 0

	// Count students by branch/group
	studentsIter := firestoreClient.Collection("students").Documents(context.Background())
	for {
		doc, err := studentsIter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Printf("[ADMIN] Error fetching student: %v", err)
			break
		}
		data := doc.Data()
		branch, _ := data["branch"].(string)

		switch branch {
		case "CSE-A", "CSE-B", "CSE-C", "CSE-D":
			cseCount++
		case "CAI", "CSM", "CSD":
			aiCount++
		case "ECE", "ECE-A", "ECE-B":
			eceCount++
		case "EEE", "EEE-A", "EEE-B":
			eeeCount++
		case "MECH", "MECH-A", "MECH-B":
			mechCount++
		case "CIVIL", "CIVIL-A", "CIVIL-B":
			civilCount++
		}
	}

	now := time.Now()
	activeSessions := []Session{}
	iter := firestoreClient.Collection("sessions").Where("is_finalized", "==", false).Documents(context.Background())
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Printf("[ADMIN] Error fetching session: %v", err)
			break
		}
		var s Session
		doc.DataTo(&s)
		s.ID = doc.Ref.ID

		// Check if session has expired and auto-finalize it
		endTimeUnix := int64(s.EndTime)
		if endTimeUnix > 0 && now.Unix() > endTimeUnix {
			// Auto-finalize this expired session
			firestoreClient.Collection("sessions").Doc(s.ID).Update(context.Background(), []firestore.Update{
				{Path: "is_finalized", Value: true},
			})
			log.Printf("[ADMIN AUTO-EXPIRE] Session %s for %s has been auto-finalized (class time ended)", s.ID, s.Subject)
			continue // Don't add to active sessions
		}

		// Fetch teacher name if not set
		if s.TeacherName == "" || s.TeacherName == s.TeacherID {
			teacherDoc, err := firestoreClient.Collection("teachers").Doc(s.TeacherID).Get(context.Background())
			if err == nil {
				if name, ok := teacherDoc.Data()["name"].(string); ok {
					s.TeacherName = name
				} else {
					s.TeacherName = s.TeacherID
				}
			}
		}

		activeSessions = append(activeSessions, s)
	}

	// Count total teachers
	totalTeachers := 0
	teacherIter := firestoreClient.Collection("users").Where("role", "==", "teacher").Documents(context.Background())
	for {
		_, err := teacherIter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			break
		}
		totalTeachers++
	}

	c.HTML(http.StatusOK, "admin.html", gin.H{
		"cse_count":       cseCount,
		"ai_count":        aiCount,
		"ece_count":       eceCount,
		"eee_count":       eeeCount,
		"mech_count":      mechCount,
		"civil_count":     civilCount,
		"active_sessions": activeSessions,
		"server_now":      now.Unix(),
		"total_students":  cseCount + aiCount + eceCount + eeeCount + mechCount + civilCount,
		"total_teachers":  totalTeachers,
		"sessions_today":  len(activeSessions),
	})
}

func viewAttendanceHandler(c *gin.Context) {
	s := sessions.Default(c)
	role := s.Get("role")
	userID := s.Get("user_id")
	if role == nil || userID == nil {
		c.Redirect(http.StatusFound, "/login")
		return
	}
	if role != "teacher" {
		if role == "admin" {
			c.Redirect(http.StatusFound, "/admin")
			return
		}
		c.Redirect(http.StatusFound, "/login")
		return
	}
	teacherID := userID.(string)

	subject := c.Query("subject")
	branch := c.Query("branch")
	date := c.Query("date")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit := 100

	records := []Attendance{}

	// Try to fetch by teacher_id first (simple query without OrderBy to avoid index requirement)
	iter := firestoreClient.Collection("attendance").Where("teacher_id", "==", teacherID).Documents(context.Background())
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Printf("[VIEW_ATTENDANCE] Error fetching by teacher_id: %v", err)
			break
		}
		var a Attendance
		doc.DataTo(&a)
		a.ID = doc.Ref.ID

		// Apply filters in Go
		if subject != "" && a.Subject != subject {
			continue
		}
		if branch != "" && a.Branch != branch {
			continue
		}
		if date != "" && a.Date != date {
			continue
		}

		records = append(records, a)
	}

	// If no records found by teacher_id, also try fetching by subjects this teacher teaches
	if len(records) == 0 {
		log.Printf("[VIEW_ATTENDANCE] No records by teacher_id, trying by subjects for: %s", teacherID)

		// Get subjects this teacher teaches
		subIter := firestoreClient.Collection("subjects").Where("teacher_id", "==", teacherID).Documents(context.Background())
		teacherSubjects := []string{}
		for {
			subDoc, err := subIter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				continue
			}
			if subName, ok := subDoc.Data()["name"].(string); ok {
				teacherSubjects = append(teacherSubjects, subName)
			}
		}

		// Fetch attendance for those subjects
		for _, subj := range teacherSubjects {
			attIter := firestoreClient.Collection("attendance").Where("subject", "==", subj).Documents(context.Background())
			for {
				doc, err := attIter.Next()
				if err == iterator.Done {
					break
				}
				if err != nil {
					continue
				}
				var a Attendance
				doc.DataTo(&a)
				a.ID = doc.Ref.ID

				// Apply filters
				if branch != "" && a.Branch != branch {
					continue
				}
				if date != "" && a.Date != date {
					continue
				}

				records = append(records, a)
			}
		}
	}

	// Sort by timestamp descending (newest first)
	sort.Slice(records, func(i, j int) bool {
		return records[i].Timestamp.After(records[j].Timestamp)
	})

	// Apply pagination
	start := (page - 1) * limit
	end := start + limit
	if start > len(records) {
		start = len(records)
	}
	if end > len(records) {
		end = len(records)
	}
	paginatedRecords := records[start:end]

	totalPages := (len(records) + limit - 1) / limit
	if totalPages < 1 {
		totalPages = 1
	}

	log.Printf("[VIEW_ATTENDANCE] Teacher %s: Found %d total records, showing %d-%d", teacherID, len(records), start, end)

	c.HTML(http.StatusOK, "view.html", gin.H{
		"records":     paginatedRecords,
		"role":        role,
		"page":        page,
		"total_pages": totalPages,
		"prev_page":   page - 1,
		"next_page":   page + 1,
		"f_subject":   subject,
		"f_branch":    branch,
		"f_date":      date,
	})
}

func classRecordsHandler(c *gin.Context) {
	branch := c.Query("branch")
	group := c.Query("group") // e.g. "CSE", "AI", "ECE"

	// Define groups and their branches
	groupBranches := map[string][]string{
		"CSE":   {"CSE-A", "CSE-B", "CSE-C", "CSE-D"},
		"AI":    {"CAI", "CSM", "CSD"},
		"ECE":   {"ECE-A", "ECE-B", "ECE"},
		"EEE":   {"EEE-A", "EEE-B", "EEE"},
		"MECH":  {"MECH-A", "MECH-B", "MECH"},
		"CIVIL": {"CIVIL-A", "CIVIL-B", "CIVIL"},
	}

	// Determine which branches to show based on group
	var validBranches []string
	if group != "" {
		if branches, ok := groupBranches[group]; ok {
			validBranches = branches
		} else {
			validBranches = []string{group} // Treat as single branch
		}
	} else {
		// Show all branches
		validBranches = []string{"CSE-A", "CSE-B", "CAI", "CSM", "CSD", "ECE", "EEE", "MECH", "CIVIL"}
	}

	// Get student count for branch
	totalStrength := 0
	var allStudents []Student
	if branch != "" {
		iter := firestoreClient.Collection("students").Where("branch", "==", branch).Documents(context.Background())
		for {
			doc, err := iter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				continue
			}
			var s Student
			if err := doc.DataTo(&s); err != nil {
				// Try manual extraction for compatibility
				data := doc.Data()
				if v := data["roll"]; v != nil {
					s.Roll = fmt.Sprint(v)
				} else if v := data["roll_no"]; v != nil {
					s.Roll = fmt.Sprint(v)
				}
				if v := data["name"]; v != nil {
					s.Name = fmt.Sprint(v)
				}
				if v := data["branch"]; v != nil {
					s.Branch = fmt.Sprint(v)
				}
				if v := data["parent_phone"]; v != nil {
					s.ParentPhone = fmt.Sprint(v)
				}
			}
			if s.Roll == "" {
				s.Roll = doc.Ref.ID
			}
			allStudents = append(allStudents, s)
			totalStrength++
		}
	}

	sort.Slice(allStudents, func(i, j int) bool {
		return strings.ToUpper(allStudents[i].Roll) < strings.ToUpper(allStudents[j].Roll)
	})

	if totalStrength == 0 {
		totalStrength = 60 // Default fallback
	}

	c.HTML(http.StatusOK, "class_records.html", gin.H{
		"group":           group,
		"selected_branch": branch,
		"branches":        validBranches,
		"students":        allStudents,
		"total_strength":  totalStrength,
	})
}

func settingsHandler(c *gin.Context) {
	config := getConfig()
	holidays := []Holiday{}
	iter := firestoreClient.Collection("holidays").OrderBy("date", firestore.Asc).Documents(context.Background())
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		var h Holiday
		doc.DataTo(&h)
		h.ID = doc.Ref.ID
		h.DateDisplay = h.Date // Format if needed
		holidays = append(holidays, h)
	}

	c.HTML(http.StatusOK, "settings.html", gin.H{
		"config":   config,
		"holidays": holidays,
	})
}

func updateSettingsHandlers(c *gin.Context) {
	session := sessions.Default(c)
	if session.Get("role") != "admin" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	settingType := c.PostForm("setting_type")

	switch settingType {
	case "semester":
		firestoreClient.Collection("config").Doc("main").Set(context.Background(), map[string]interface{}{
			"start_date": c.PostForm("start_date"),
			"end_date":   c.PostForm("end_date"),
		}, firestore.MergeAll)
	case "geofencing":
		enabled := c.PostForm("geo_enabled") == "on"
		rad, _ := strconv.ParseFloat(c.PostForm("geo_radius"), 64)
		lat, _ := strconv.ParseFloat(c.PostForm("college_lat"), 64)
		lng, _ := strconv.ParseFloat(c.PostForm("college_lng"), 64)
		firestoreClient.Collection("config").Doc("main").Set(context.Background(), map[string]interface{}{
			"geo_enabled": enabled,
			"geo_radius":  rad,
			"college_lat": lat,
			"college_lng": lng,
		}, firestore.MergeAll)
	case "sms":
		enabled := c.PostForm("sms_enabled") == "on"
		thresh, _ := strconv.Atoi(c.PostForm("sms_threshold"))
		firestoreClient.Collection("config").Doc("main").Set(context.Background(), map[string]interface{}{
			"sms_enabled":     enabled,
			"sms_sid":         c.PostForm("sms_sid"),
			"sms_auth_token":  c.PostForm("sms_auth_token"),
			"sms_from_number": c.PostForm("sms_from_number"),
			"sms_threshold":   thresh,
		}, firestore.MergeAll)
	case "email":
		enabled := c.PostForm("email_enabled") == "on"
		port, _ := strconv.Atoi(c.PostForm("smtp_port"))
		firestoreClient.Collection("config").Doc("main").Set(context.Background(), map[string]interface{}{
			"email_enabled":  enabled,
			"smtp_server":    c.PostForm("smtp_server"),
			"smtp_port":      port,
			"email_from":     c.PostForm("email_from"),
			"email_password": c.PostForm("email_password"),
		}, firestore.MergeAll)
	}

	c.Redirect(http.StatusFound, "/settings")
}

// ... Additional handlers for other pages

func main() {
	// Load .env file if it exists
	if err := godotenv.Load(); err != nil {
		log.Println("[CONFIG] No .env file found, using system environment variables")
	}

	initFirebase()
	r := gin.Default()
	r.LoadHTMLGlob("templates/*")
	r.Static("/static", "./static")

	// Session secret from environment variable (security hardening)
	sessionSecret := os.Getenv("SESSION_SECRET")
	if sessionSecret == "" {
		// Generate a random secret if not set (for development)
		log.Println("[SECURITY] WARNING: SESSION_SECRET not set, using generated secret. Set SESSION_SECRET env var in production!")
		b := make([]byte, 32)
		rand.Read(b)
		sessionSecret = base64.StdEncoding.EncodeToString(b)
	}
	store := cookie.NewStore([]byte(sessionSecret))

	// Detect if running in production (Render sets PORT env var)
	isProduction := os.Getenv("PORT") != ""

	store.Options(sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7,    // 7 days
		HttpOnly: true,         // Prevent XSS attacks
		Secure:   isProduction, // true for HTTPS (Render), false for local HTTP
		SameSite: http.SameSiteLaxMode,
	})
	r.Use(sessions.Sessions("qr_session", store))

	r.GET("/", func(c *gin.Context) { c.Redirect(http.StatusFound, "/login") })
	r.GET("/login", loginHandler)
	r.POST("/login", loginHandler)
	r.GET("/register", registerHandler)
	r.POST("/register", registerHandler)
	r.GET("/logout", func(c *gin.Context) {
		s := sessions.Default(c)
		s.Clear()
		s.Save()
		c.Redirect(http.StatusFound, "/login")
	})

	// Success page for attendance submission
	r.GET("/success", func(c *gin.Context) {
		c.HTML(http.StatusOK, "success.html", nil)
	})

	// Teacher
	r.GET("/teacher", teacherDashboard)
	r.POST("/teacher/add_subject", addSubjectHandler)
	r.POST("/teacher/delete_subject", deleteSubjectHandler)
	r.POST("/teacher/start_session", startSessionHandler)
	r.POST("/teacher/finalize_session", finalizeSessionHandler)

	// JSON API for starting session (used by JavaScript in teacher dashboard)
	r.POST("/start_session", func(c *gin.Context) {
		session := sessions.Default(c)
		userID := session.Get("user_id")
		if userID == nil || session.Get("role") != "teacher" {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Not authorized"})
			return
		}
		teacherID := userID.(string)

		var data struct {
			Subject   string `json:"subject"`
			Branch    string `json:"branch"`
			ClassType string `json:"class_type"`
		}
		if err := c.BindJSON(&data); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid request"})
			return
		}

		now := time.Now()
		duration := 1.0
		if data.ClassType == "Lab" {
			duration = 3.0
		}
		endTime := now.Add(time.Duration(duration) * time.Hour)
		qrToken := fmt.Sprintf("%d-%s", now.UnixNano(), teacherID)

		// Get teacher name
		teacherName := teacherID
		teacherDoc, err := firestoreClient.Collection("teachers").Doc(teacherID).Get(context.Background())
		if err == nil && teacherDoc.Exists() {
			if v := teacherDoc.Data()["name"]; v != nil && fmt.Sprint(v) != "" {
				teacherName = fmt.Sprint(v)
			}
		}

		newSession := map[string]interface{}{
			"teacher_id":   teacherID,
			"teacher_name": teacherName,
			"subject":      data.Subject,
			"branch":       data.Branch,
			"class_type":   data.ClassType,
			"start_time":   float64(now.Unix()),
			"end_time":     float64(endTime.Unix()),
			"is_finalized": false,
			"qr_token":     qrToken,
			"date":         now.Format("2006-01-02"),
			"time":         now.Format("15:04:05"),
		}

		ref, _, err := firestoreClient.Collection("sessions").Add(context.Background(), newSession)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": err.Error()})
			return
		}

		log.Printf("[SESSION] Created session %s for teacher %s, subject: %s, branch: %s", ref.ID, teacherID, data.Subject, data.Branch)

		c.JSON(http.StatusOK, gin.H{
			"success":       true,
			"session_id":    ref.ID,
			"token":         qrToken,
			"end_time":      now.Format("15:04") + " - " + endTime.Format("15:04"),
			"end_timestamp": endTime.Unix(),
		})
	})

	// JSON API for finalizing session (used by JavaScript)
	r.POST("/finalize_session", func(c *gin.Context) {
		session := sessions.Default(c)
		userID := session.Get("user_id")
		role := session.Get("role")
		if userID == nil || (role != "teacher" && role != "admin") {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Not authorized"})
			return
		}

		var data struct {
			SessionID string `json:"session_id"`
		}
		if err := c.BindJSON(&data); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid request"})
			return
		}

		// Get session details first
		sessionDoc, err := firestoreClient.Collection("sessions").Doc(data.SessionID).Get(context.Background())
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "message": "Session not found"})
			return
		}

		sessionData := sessionDoc.Data()
		subject, _ := sessionData["subject"].(string)
		branch, _ := sessionData["branch"].(string)
		teacherID, _ := sessionData["teacher_id"].(string)
		date, _ := sessionData["date"].(string)

		// Mark session as finalized
		_, err = firestoreClient.Collection("sessions").Doc(data.SessionID).Update(context.Background(), []firestore.Update{
			{Path: "is_finalized", Value: true},
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Failed to finalize session"})
			return
		}

		// Get all students who marked attendance for this session
		presentStudents := make(map[string]bool)
		attIter := firestoreClient.Collection("attendance").Where("session_id", "==", data.SessionID).Documents(context.Background())
		for {
			doc, err := attIter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				continue
			}
			roll, _ := doc.Data()["roll"].(string)
			presentStudents[roll] = true
		}

		// Get all students in the branch and mark absent for those who didn't attend
		studIter := firestoreClient.Collection("students").Where("branch", "==", branch).Documents(context.Background())
		absentCount := 0
		for {
			doc, err := studIter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				continue
			}
			studentData := doc.Data()
			roll := doc.Ref.ID
			if studentData["roll"] != nil {
				roll = fmt.Sprint(studentData["roll"])
			}
			name, _ := studentData["name"].(string)

			if !presentStudents[roll] {
				// Mark as absent
				absentRecord := map[string]interface{}{
					"session_id": data.SessionID,
					"roll":       roll,
					"name":       name,
					"subject":    subject,
					"branch":     branch,
					"teacher_id": teacherID,
					"date":       date,
					"time":       time.Now().Format("15:04:05"),
					"timestamp":  time.Now(),
					"status":     "ABSENT",
				}
				firestoreClient.Collection("attendance").Add(context.Background(), absentRecord)
				absentCount++
			}
		}

		log.Printf("[FINALIZE] Session %s finalized. Present: %d, Absent: %d", data.SessionID, len(presentStudents), absentCount)

		c.JSON(http.StatusOK, gin.H{
			"success":       true,
			"message":       "Session finalized",
			"present_count": len(presentStudents),
			"absent_count":  absentCount,
		})
	})

	r.POST("/teacher/update_profile", func(c *gin.Context) {
		session := sessions.Default(c)
		userID := session.Get("user_id")
		if userID == nil || session.Get("role") != "teacher" {
			c.Redirect(http.StatusFound, "/login")
			return
		}
		teacherID := userID.(string)

		// Get form data
		fullName := c.PostForm("full_name")
		email := c.PostForm("email")
		phone := c.PostForm("phone")
		department := c.PostForm("department")

		// Handle profile picture upload
		profilePic := ""
		file, err := c.FormFile("profile_pic")
		if err == nil && file != nil {
			// Save uploaded file
			filename := fmt.Sprintf("profile_%s_%d%s", teacherID, time.Now().Unix(), filepath.Ext(file.Filename))
			savePath := filepath.Join("static", "proofs", filename)
			if err := c.SaveUploadedFile(file, savePath); err == nil {
				profilePic = "/static/proofs/" + filename
			}
		}

		// Update teacher document
		updateData := map[string]interface{}{
			"name":       fullName,
			"email":      email,
			"phone":      phone,
			"department": department,
		}
		if profilePic != "" {
			updateData["profile_pic"] = profilePic
		}

		_, err = firestoreClient.Collection("teachers").Doc(teacherID).Set(context.Background(), updateData, firestore.MergeAll)
		if err != nil {
			log.Printf("[TEACHER] Error updating profile: %v", err)
		}

		c.Redirect(http.StatusFound, "/teacher")
	})

	// Admin
	r.GET("/admin", adminDashboard)
	r.GET("/view_attendance", viewAttendanceHandler)
	r.GET("/class_records", classRecordsHandler)
	r.GET("/settings", settingsHandler)

	// Admin - Get all teachers
	r.GET("/admin/get_teachers", func(c *gin.Context) {
		session := sessions.Default(c)
		if session.Get("role") != "admin" {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Not authorized"})
			return
		}

		// Get all users with role "teacher"
		iter := firestoreClient.Collection("users").Where("role", "==", "teacher").Documents(context.Background())
		var teachers []map[string]interface{}

		for {
			doc, err := iter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				continue
			}

			data := doc.Data()
			teacherID := doc.Ref.ID

			// Get actual teacher name from teachers collection
			teacherName := teacherID // Default to ID
			teacherDoc, err := firestoreClient.Collection("teachers").Doc(teacherID).Get(context.Background())
			if err == nil && teacherDoc.Exists() {
				if name := teacherDoc.Data()["name"]; name != nil && fmt.Sprint(name) != "" {
					teacherName = fmt.Sprint(name)
				}
			}

			// Count subjects for this teacher
			subjectsIter := firestoreClient.Collection("subjects").Where("teacher_id", "==", teacherID).Documents(context.Background())
			subjectCount := 0
			for {
				_, err := subjectsIter.Next()
				if err == iterator.Done {
					break
				}
				if err == nil {
					subjectCount++
				}
			}

			teachers = append(teachers, map[string]interface{}{
				"teacher_id":    teacherID,
				"name":          teacherName,
				"email":         data["email"],
				"subject_count": subjectCount,
			})
		}

		if teachers == nil {
			teachers = []map[string]interface{}{}
		}

		c.JSON(http.StatusOK, gin.H{"success": true, "teachers": teachers})
	})

	// Admin - Get teacher session history (Teacher Attendance Record)
	r.GET("/admin/teacher_session_history", func(c *gin.Context) {
		session := sessions.Default(c)
		if session.Get("role") != "admin" {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Not authorized"})
			return
		}

		// Get all finalized sessions
		// Note: Removed OrderBy to avoid needing a Firestore composite index
		iter := firestoreClient.Collection("sessions").Where("is_finalized", "==", true).Limit(100).Documents(context.Background())
		var history []map[string]interface{}

		for {
			doc, err := iter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				continue
			}

			data := doc.Data()
			sessionID := doc.Ref.ID

			// Count students who attended this session
			attIter := firestoreClient.Collection("attendance").Where("session_id", "==", sessionID).Documents(context.Background())
			studentCount := 0
			for {
				_, err := attIter.Next()
				if err == iterator.Done {
					break
				}
				if err == nil {
					studentCount++
				}
			}

			// Parse times for display - use IST timezone
			ist, _ := time.LoadLocation("Asia/Kolkata")
			startTime, _ := data["start_time"].(float64)
			endTime, _ := data["end_time"].(float64)
			startTimeStr := time.Unix(int64(startTime), 0).In(ist).Format("15:04")
			endTimeStr := time.Unix(int64(endTime), 0).In(ist).Format("15:04")

			history = append(history, map[string]interface{}{
				"session_id":    sessionID,
				"teacher_name":  data["teacher_name"],
				"subject":       data["subject"],
				"branch":        data["branch"],
				"class_type":    data["class_type"],
				"date":          data["date"],
				"start_time":    startTimeStr,
				"end_time":      endTimeStr,
				"student_count": studentCount,
			})
		}

		if history == nil {
			history = []map[string]interface{}{}
		}

		c.JSON(http.StatusOK, gin.H{"success": true, "history": history})
	})

	// Admin - Get pending teacher registrations
	r.GET("/admin/pending-teachers", func(c *gin.Context) {
		session := sessions.Default(c)
		if session.Get("role") != "admin" {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Not authorized"})
			return
		}

		// Get all pending teacher registrations
		iter := firestoreClient.Collection("pending_teacher_registrations").Where("status", "==", "PENDING").Documents(context.Background())
		var pending []map[string]interface{}

		for {
			doc, err := iter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				continue
			}

			data := doc.Data()
			pending = append(pending, map[string]interface{}{
				"id":         doc.Ref.ID,
				"teacher_id": data["teacher_id"],
				"full_name":  data["full_name"],
				"email":      data["email"],
				"phone":      data["phone"],
				"created_at": data["created_at"],
			})
		}

		if pending == nil {
			pending = []map[string]interface{}{}
		}

		c.JSON(http.StatusOK, gin.H{"success": true, "pending": pending})
	})

	// Admin - Approve teacher registration
	r.POST("/admin/approve-teacher", func(c *gin.Context) {
		session := sessions.Default(c)
		if session.Get("role") != "admin" {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Not authorized"})
			return
		}

		var data struct {
			RegistrationID string `json:"registration_id"`
		}
		if err := c.BindJSON(&data); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid request"})
			return
		}

		// Get pending registration
		doc, err := firestoreClient.Collection("pending_teacher_registrations").Doc(data.RegistrationID).Get(context.Background())
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "message": "Registration not found"})
			return
		}

		var pending PendingTeacherRegistration
		doc.DataTo(&pending)

		// Check if already processed
		if pending.Status != "PENDING" {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Registration already processed"})
			return
		}

		// Create user account
		user := User{
			Username:  pending.TeacherID,
			Password:  pending.Password,
			Role:      "teacher",
			Email:     pending.Email,
			CreatedAt: time.Now(),
		}
		_, err = firestoreClient.Collection("users").Doc(pending.TeacherID).Set(context.Background(), user)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Failed to create user: " + err.Error()})
			return
		}

		// Create teacher record
		teacherData := map[string]interface{}{
			"name":       pending.FullName,
			"email":      pending.Email,
			"phone":      pending.Phone,
			"created_at": time.Now(),
		}
		_, err = firestoreClient.Collection("teachers").Doc(pending.TeacherID).Set(context.Background(), teacherData)
		if err != nil {
			log.Printf("Error creating teacher record: %v", err)
		}

		// Update pending registration status
		firestoreClient.Collection("pending_teacher_registrations").Doc(data.RegistrationID).Update(context.Background(), []firestore.Update{
			{Path: "status", Value: "APPROVED"},
			{Path: "reviewed_at", Value: time.Now()},
		})

		log.Printf("[ADMIN] Teacher registration approved: %s (%s)", pending.TeacherID, pending.FullName)
		c.JSON(http.StatusOK, gin.H{"success": true, "message": "Teacher registration approved"})
	})

	// Admin - Reject teacher registration
	r.POST("/admin/reject-teacher", func(c *gin.Context) {
		session := sessions.Default(c)
		if session.Get("role") != "admin" {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Not authorized"})
			return
		}

		var data struct {
			RegistrationID string `json:"registration_id"`
			Remarks        string `json:"remarks"`
		}
		if err := c.BindJSON(&data); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid request"})
			return
		}

		// Get pending registration
		doc, err := firestoreClient.Collection("pending_teacher_registrations").Doc(data.RegistrationID).Get(context.Background())
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "message": "Registration not found"})
			return
		}

		var pending PendingTeacherRegistration
		doc.DataTo(&pending)

		if pending.Status != "PENDING" {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Registration already processed"})
			return
		}

		// Update pending registration status to rejected
		firestoreClient.Collection("pending_teacher_registrations").Doc(data.RegistrationID).Update(context.Background(), []firestore.Update{
			{Path: "status", Value: "REJECTED"},
			{Path: "reviewed_at", Value: time.Now()},
			{Path: "admin_remarks", Value: data.Remarks},
		})

		log.Printf("[ADMIN] Teacher registration rejected: %s (%s)", pending.TeacherID, pending.FullName)
		c.JSON(http.StatusOK, gin.H{"success": true, "message": "Teacher registration rejected"})
	})

	// Student
	r.GET("/student", studentDashboard)
	r.POST("/student/update_profile", func(c *gin.Context) {
		session := sessions.Default(c)
		userID := session.Get("user_id")
		if userID == nil || session.Get("role") != "student" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authorized"})
			return
		}
		studentID := userID.(string)

		name := c.PostForm("name")
		email := c.PostForm("email")
		branch := c.PostForm("branch")

		// Get current student data (may not exist for older accounts)
		doc, err := firestoreClient.Collection("students").Doc(studentID).Get(context.Background())

		currentBranch := ""
		if err == nil && doc.Exists() {
			if v := doc.Data()["branch"]; v != nil {
				currentBranch = fmt.Sprint(v)
			}
		}

		updates := map[string]interface{}{
			"roll_no": studentID,
		}

		// Name can always be updated
		if name != "" {
			updates["name"] = name
		}

		// Email can always be updated
		if email != "" {
			updates["email"] = email
		}

		// Branch can only be set once (if currently empty)
		if branch != "" && (currentBranch == "" || currentBranch == "<nil>") {
			updates["branch"] = branch
		} else if branch != "" && currentBranch != "" && currentBranch != "<nil>" {
			// Branch already set, don't allow change
			c.JSON(http.StatusBadRequest, gin.H{"error": "Branch can only be set once", "branch_locked": true})
			return
		}

		if len(updates) > 1 { // More than just roll_no
			_, err = firestoreClient.Collection("students").Doc(studentID).Set(context.Background(), updates, firestore.MergeAll)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
		}

		c.JSON(http.StatusOK, gin.H{"success": true, "message": "Profile updated successfully"})
	})

	// Timetable API endpoints
	r.GET("/api/timetable", func(c *gin.Context) {
		session := sessions.Default(c)
		userID := session.Get("user_id")
		if userID == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Not logged in"})
			return
		}
		teacherID := userID.(string)

		// Fetch timetable entries for this teacher
		iter := firestoreClient.Collection("timetable").Where("teacher_id", "==", teacherID).Documents(context.Background())
		entries := []map[string]interface{}{}
		for {
			doc, err := iter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				break
			}
			data := doc.Data()
			data["id"] = doc.Ref.ID
			entries = append(entries, data)
		}
		c.JSON(http.StatusOK, gin.H{"entries": entries})
	})

	r.POST("/api/timetable/add", func(c *gin.Context) {
		session := sessions.Default(c)
		userID := session.Get("user_id")
		if userID == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Not logged in"})
			return
		}
		teacherID := userID.(string)

		var data struct {
			Day       string `json:"day"`
			SlotIndex int    `json:"slot_index"`
			Subject   string `json:"subject"`
			ClassName string `json:"class_name"`
			ClassType string `json:"type"`
			TimeSlot  string `json:"time_slot"`
		}
		if err := c.BindJSON(&data); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid data"})
			return
		}

		// Check if slot already occupied
		cellKey := fmt.Sprintf("%s_%d", data.Day, data.SlotIndex)
		existIter := firestoreClient.Collection("timetable").
			Where("teacher_id", "==", teacherID).
			Where("cell_key", "==", cellKey).
			Documents(context.Background())
		existDoc, _ := existIter.Next()
		if existDoc != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Slot already occupied"})
			return
		}

		// Add timetable entry
		entry := map[string]interface{}{
			"teacher_id": teacherID,
			"day":        data.Day,
			"slot_index": data.SlotIndex,
			"cell_key":   cellKey,
			"subject":    data.Subject,
			"class_name": data.ClassName,
			"type":       data.ClassType,
			"time_slot":  data.TimeSlot,
			"created_at": time.Now(),
		}

		docRef, _, err := firestoreClient.Collection("timetable").Add(context.Background(), entry)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save"})
			return
		}

		// Also add to subjects collection for attendance dropdown
		subjectEntry := map[string]interface{}{
			"teacher_id":  teacherID,
			"name":        data.Subject,
			"branch":      data.ClassName,
			"day_of_week": data.Day,
			"time_slot":   data.TimeSlot,
			"class_type":  data.ClassType,
		}
		firestoreClient.Collection("subjects").Add(context.Background(), subjectEntry)

		c.JSON(http.StatusOK, gin.H{"success": true, "id": docRef.ID})
	})

	r.POST("/api/timetable/delete", func(c *gin.Context) {
		session := sessions.Default(c)
		userID := session.Get("user_id")
		if userID == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Not logged in"})
			return
		}
		teacherID := userID.(string)

		var data struct {
			CellKey string `json:"cell_key"`
		}
		if err := c.BindJSON(&data); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid data"})
			return
		}

		// Find and delete the timetable entry
		iter := firestoreClient.Collection("timetable").
			Where("teacher_id", "==", teacherID).
			Where("cell_key", "==", data.CellKey).
			Documents(context.Background())

		doc, err := iter.Next()
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Entry not found"})
			return
		}

		// Get subject info before deleting
		docData := doc.Data()
		subject := fmt.Sprint(docData["subject"])
		className := fmt.Sprint(docData["class_name"])

		// Delete from timetable
		doc.Ref.Delete(context.Background())

		// Also delete from subjects collection
		subIter := firestoreClient.Collection("subjects").
			Where("teacher_id", "==", teacherID).
			Where("name", "==", subject).
			Where("branch", "==", className).
			Documents(context.Background())
		subDoc, _ := subIter.Next()
		if subDoc != nil {
			subDoc.Ref.Delete(context.Background())
		}

		c.JSON(http.StatusOK, gin.H{"success": true})
	})

	r.POST("/api/timetable/clear", func(c *gin.Context) {
		session := sessions.Default(c)
		userID := session.Get("user_id")
		if userID == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Not logged in"})
			return
		}
		teacherID := userID.(string)

		// Delete all timetable entries for this teacher
		iter := firestoreClient.Collection("timetable").Where("teacher_id", "==", teacherID).Documents(context.Background())
		batch := firestoreClient.Batch()
		count := 0
		for {
			doc, err := iter.Next()
			if err == iterator.Done {
				break
			}
			batch.Delete(doc.Ref)
			count++
		}
		if count > 0 {
			batch.Commit(context.Background())
		}

		// Also clear subjects
		subIter := firestoreClient.Collection("subjects").Where("teacher_id", "==", teacherID).Documents(context.Background())
		subBatch := firestoreClient.Batch()
		for {
			doc, err := subIter.Next()
			if err == iterator.Done {
				break
			}
			subBatch.Delete(doc.Ref)
		}
		subBatch.Commit(context.Background())

		c.JSON(http.StatusOK, gin.H{"success": true, "deleted": count})
	})

	// Debug route - check all attendance records
	r.GET("/debug_attendance", func(c *gin.Context) {
		roll := c.Query("roll")
		iter := firestoreClient.Collection("attendance").Documents(context.Background())
		records := []map[string]interface{}{}
		for {
			doc, err := iter.Next()
			if err == iterator.Done {
				break
			}
			data := doc.Data()
			data["_id"] = doc.Ref.ID
			if roll == "" || data["roll"] == roll {
				records = append(records, data)
			}
		}
		c.JSON(http.StatusOK, gin.H{"count": len(records), "records": records})
	})

	// Debug endpoint to check teacher data
	r.GET("/debug_teacher", func(c *gin.Context) {
		session := sessions.Default(c)
		userID := session.Get("user_id")
		role := session.Get("role")

		if userID == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Not logged in"})
			return
		}

		teacherID := userID.(string)
		result := gin.H{
			"user_id":          teacherID,
			"role":             role,
			"subjects_count":   0,
			"subjects":         []map[string]interface{}{},
			"attendance_count": 0,
			"attendance":       []map[string]interface{}{},
		}

		// Get subjects for this teacher
		subIter := firestoreClient.Collection("subjects").Where("teacher_id", "==", teacherID).Documents(context.Background())
		subjects := []map[string]interface{}{}
		subjectNames := []string{}
		for {
			doc, err := subIter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				continue
			}
			data := doc.Data()
			data["_id"] = doc.Ref.ID
			subjects = append(subjects, data)
			if name, ok := data["name"].(string); ok {
				subjectNames = append(subjectNames, name)
			}
		}
		result["subjects"] = subjects
		result["subjects_count"] = len(subjects)
		result["subject_names"] = subjectNames

		// Get attendance by teacher_id
		attIter := firestoreClient.Collection("attendance").Where("teacher_id", "==", teacherID).Documents(context.Background())
		attendance := []map[string]interface{}{}
		for {
			doc, err := attIter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				continue
			}
			data := doc.Data()
			data["_id"] = doc.Ref.ID
			attendance = append(attendance, data)
		}
		result["attendance"] = attendance
		result["attendance_count"] = len(attendance)

		// Also get all attendance to see if any exists
		allIter := firestoreClient.Collection("attendance").Limit(10).Documents(context.Background())
		allAttendance := []map[string]interface{}{}
		for {
			doc, err := allIter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				continue
			}
			data := doc.Data()
			data["_id"] = doc.Ref.ID
			allAttendance = append(allAttendance, data)
		}
		result["all_attendance_sample"] = allAttendance
		result["all_attendance_sample_count"] = len(allAttendance)

		c.JSON(http.StatusOK, result)
	})

	// Settings & Config Handlers
	r.POST("/update_semester_dates", func(c *gin.Context) {
		fs := firestoreClient.Collection("config").Doc("main")
		fs.Set(context.Background(), map[string]interface{}{
			"start_date": c.PostForm("start_date"),
			"end_date":   c.PostForm("end_date"),
		}, firestore.MergeAll)
		c.Redirect(http.StatusFound, "/settings")
	})

	r.POST("/update_geofencing", func(c *gin.Context) {
		enabled := c.PostForm("geo_enabled") == "on"
		rad, _ := strconv.ParseFloat(c.PostForm("geo_radius"), 64)
		lat, _ := strconv.ParseFloat(c.PostForm("college_lat"), 64)
		lng, _ := strconv.ParseFloat(c.PostForm("college_lng"), 64)

		firestoreClient.Collection("config").Doc("main").Set(context.Background(), map[string]interface{}{
			"geo_enabled": enabled,
			"geo_radius":  rad,
			"college_lat": lat,
			"college_lng": lng,
		}, firestore.MergeAll)
		c.Redirect(http.StatusFound, "/settings")
	})

	r.POST("/update_sms_config", func(c *gin.Context) {
		enabled := c.PostForm("sms_enabled") == "on"
		thresh, _ := strconv.Atoi(c.PostForm("sms_threshold"))
		firestoreClient.Collection("config").Doc("main").Set(context.Background(), map[string]interface{}{
			"sms_enabled":     enabled,
			"sms_sid":         c.PostForm("sms_sid"),
			"sms_auth_token":  c.PostForm("sms_auth_token"),
			"sms_from_number": c.PostForm("sms_from_number"),
			"sms_threshold":   thresh,
		}, firestore.MergeAll)
		c.Redirect(http.StatusFound, "/settings")
	})

	r.POST("/admin/add_holiday", func(c *gin.Context) {
		// JS fetch POST
		var h Holiday
		if err := c.BindJSON(&h); err == nil {
			h.DateDisplay = h.Date // Simplified
			firestoreClient.Collection("holidays").Add(context.Background(), h)
			c.JSON(http.StatusOK, gin.H{"success": true})
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
	})

	r.POST("/admin/delete_holiday", func(c *gin.Context) {
		// Implement if needed for JS fetch
		var data struct{ id string }
		c.BindJSON(&data)
		// firestoreClient.Collection("holidays").Doc(data.id).Delete(...)
		c.JSON(http.StatusOK, gin.H{"success": true})
	})

	r.POST("/add_student_manual", func(c *gin.Context) {
		var s Student
		if err := c.BindJSON(&s); err == nil {
			_, err := firestoreClient.Collection("students").Doc(s.Roll).Set(context.Background(), s)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": err.Error()})
			} else {
				c.JSON(http.StatusOK, gin.H{"success": true, "message": "Student added"})
			}
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Bad Request"})
		}
	})

	r.POST("/delete_students", func(c *gin.Context) {
		session := sessions.Default(c)
		if session.Get("role") != "admin" {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Unauthorized"})
			return
		}

		var data struct {
			Branch    string   `json:"branch"`
			RollNos   []string `json:"roll_nos"`
			DeleteAll bool     `json:"delete_all"`
		}
		if err := c.BindJSON(&data); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid request"})
			return
		}

		deletedCount := 0
		ctx := context.Background()

		if data.DeleteAll && data.Branch != "" {
			// Delete all students in a branch
			iter := firestoreClient.Collection("students").Where("branch", "==", data.Branch).Documents(ctx)
			batch := firestoreClient.Batch()
			batchCount := 0

			for {
				doc, err := iter.Next()
				if err == iterator.Done {
					break
				}
				if err != nil {
					continue
				}

				// Delete from students collection
				batch.Delete(doc.Ref)

				// Also delete from users collection
				userRef := firestoreClient.Collection("users").Doc(doc.Ref.ID)
				batch.Delete(userRef)

				batchCount++
				deletedCount++

				// Firestore batch limit is 500
				if batchCount >= 400 {
					batch.Commit(ctx)
					batch = firestoreClient.Batch()
					batchCount = 0
				}
			}
			if batchCount > 0 {
				batch.Commit(ctx)
			}
		} else if len(data.RollNos) > 0 {
			// Delete specific students by roll number
			batch := firestoreClient.Batch()
			for _, roll := range data.RollNos {
				studentRef := firestoreClient.Collection("students").Doc(roll)
				userRef := firestoreClient.Collection("users").Doc(roll)
				batch.Delete(studentRef)
				batch.Delete(userRef)
				deletedCount++
			}
			batch.Commit(ctx)
		}

		log.Printf("[ADMIN] Deleted %d students (Branch: %s, DeleteAll: %v)", deletedCount, data.Branch, data.DeleteAll)
		c.JSON(http.StatusOK, gin.H{"success": true, "message": fmt.Sprintf("Deleted %d students", deletedCount), "deleted_count": deletedCount})
	})

	r.POST("/upload_students", func(c *gin.Context) {
		file, _ := c.FormFile("file")
		if file != nil {
			f, _ := file.Open()
			defer f.Close()
			reader := csv.NewReader(f)
			records, _ := reader.ReadAll()

			batch := firestoreClient.Batch()
			count := 0
			imported := 0
			skipped := 0

			for i, row := range records {
				if i == 0 {
					continue // Skip header
				}
				if len(row) < 3 {
					skipped++
					continue
				}

				// Support CSV format: Roll, Name, Branch, ParentPhone (optional), Email (optional)
				s := Student{
					Roll:   strings.TrimSpace(row[0]),
					Name:   strings.TrimSpace(row[1]),
					Branch: strings.TrimSpace(row[2]),
				}

				if s.Roll == "" || s.Name == "" {
					skipped++
					continue
				}

				// Optional parent phone
				if len(row) >= 4 && row[3] != "" {
					s.ParentPhone = strings.TrimSpace(row[3])
				}

				ref := firestoreClient.Collection("students").Doc(s.Roll)
				batch.Set(ref, s)
				count++
				imported++

				if count >= 400 {
					batch.Commit(context.Background())
					batch = firestoreClient.Batch()
					count = 0
				}
			}
			if count > 0 {
				batch.Commit(context.Background())
			}

			log.Printf("[UPLOAD] Imported %d students, skipped %d rows", imported, skipped)
		}
		c.Redirect(http.StatusFound, "/settings")
	})

	r.POST("/api/test_sms", func(c *gin.Context) {
		// Mock success for now
		c.JSON(http.StatusOK, gin.H{"success": true})
	})

	// Password hint API for forgot password
	r.GET("/api/password_hint", func(c *gin.Context) {
		username := c.Query("username")
		if username == "" {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Username is required"})
			return
		}

		// Look up user in Firebase
		doc, err := firestoreClient.Collection("users").Doc(username).Get(context.Background())
		if err != nil || !doc.Exists() {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "message": "Username not found. Please check and try again."})
			return
		}

		userData := doc.Data()
		email := ""
		role := ""
		if v := userData["email"]; v != nil {
			email = fmt.Sprint(v)
		}
		if v := userData["role"]; v != nil {
			role = fmt.Sprint(v)
		}

		// Generate a password hint (show first 2 and last 1 characters if password exists)
		hint := "Your password was set during registration."

		// Mask email for privacy
		maskedEmail := ""
		if email != "" {
			parts := strings.Split(email, "@")
			if len(parts) == 2 && len(parts[0]) > 2 {
				maskedEmail = parts[0][:2] + "***@" + parts[1]
			} else if email != "" {
				maskedEmail = "***@***"
			}
		}

		// Provide role-specific hint
		roleHint := ""
		if role == "student" {
			roleHint = " (Student account - try your roll number as password if you haven't changed it)"
		} else if role == "teacher" {
			roleHint = " (Teacher account)"
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"hint":    hint + roleHint,
			"email":   maskedEmail,
			"role":    role,
		})
	})

	// Password Reset Request - sends reset link via email
	r.POST("/api/password_reset_request", func(c *gin.Context) {
		var data struct {
			Username string `json:"username"`
		}
		if err := c.BindJSON(&data); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid request"})
			return
		}

		// Rate limit password reset requests
		clientIP := c.ClientIP()
		if !apiLimiter.Allow(clientIP + "_reset") {
			c.JSON(http.StatusTooManyRequests, gin.H{"success": false, "message": "Too many reset requests. Please wait and try again."})
			return
		}

		// Look up user
		doc, err := firestoreClient.Collection("users").Doc(data.Username).Get(context.Background())
		if err != nil || !doc.Exists() {
			// Don't reveal if user exists
			c.JSON(http.StatusOK, gin.H{"success": true, "message": "If an account exists with this username, a reset link will be sent to the registered email."})
			return
		}

		userData := doc.Data()
		email := ""
		if v := userData["email"]; v != nil {
			email = fmt.Sprint(v)
		}

		if email == "" {
			c.JSON(http.StatusOK, gin.H{"success": true, "message": "If an account exists with this username, a reset link will be sent to the registered email."})
			return
		}

		// Generate reset token
		tokenBytes := make([]byte, 32)
		rand.Read(tokenBytes)
		resetToken := base64.URLEncoding.EncodeToString(tokenBytes)

		// Store reset token with expiry (1 hour)
		resetData := map[string]interface{}{
			"username":   data.Username,
			"token":      resetToken,
			"expires_at": time.Now().Add(time.Hour),
			"used":       false,
		}
		firestoreClient.Collection("password_resets").Doc(resetToken).Set(context.Background(), resetData)

		// Get email config
		config := getConfig()
		if !config.EmailEnabled || config.EmailFrom == "" {
			log.Printf("[PASSWORD_RESET] Email not configured, token for %s: %s", data.Username, resetToken)
			c.JSON(http.StatusOK, gin.H{"success": true, "message": "If an account exists with this username, a reset link will be sent to the registered email."})
			return
		}

		// Build reset URL
		scheme := "https"
		host := c.Request.Host
		if strings.Contains(host, "localhost") || strings.Contains(host, "127.0.0.1") {
			scheme = "http"
		}
		resetURL := fmt.Sprintf("%s://%s/reset_password?token=%s", scheme, host, resetToken)

		// Send reset email
		subject := "Password Reset - QR Attendance System"
		body := fmt.Sprintf(`
		<html>
		<body style="font-family: Arial, sans-serif; padding: 20px;">
			<div style="max-width: 500px; margin: 0 auto; background: #f8f9fa; padding: 30px; border-radius: 15px;">
				<h2 style="color: #667eea; margin: 0 0 20px 0;">Password Reset Request</h2>
				<p>You requested a password reset for your QR Attendance account.</p>
				<p>Click the button below to reset your password:</p>
				<p style="text-align: center; margin: 30px 0;">
					<a href="%s" style="background: linear-gradient(135deg, #667eea, #764ba2); color: white; padding: 15px 30px; text-decoration: none; border-radius: 10px; display: inline-block;">Reset Password</a>
				</p>
				<p style="font-size: 0.9em; color: #666;">This link will expire in 1 hour.</p>
				<p style="font-size: 0.9em; color: #666;">If you didn't request this, you can ignore this email.</p>
				<hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
				<p style="font-size: 0.8em; color: #999;">Chaitanya Engineering College - QR Attendance System</p>
			</div>
		</body>
		</html>`, resetURL)

		msg := "From: " + config.EmailFrom + "\r\n" +
			"To: " + email + "\r\n" +
			"Subject: " + subject + "\r\n" +
			"MIME-Version: 1.0\r\n" +
			"Content-Type: text/html; charset=UTF-8\r\n" +
			"\r\n" + body

		auth := smtp.PlainAuth("", config.EmailFrom, config.EmailPassword, config.SMTPServer)
		addr := fmt.Sprintf("%s:%d", config.SMTPServer, config.SMTPPort)

		err = smtp.SendMail(addr, auth, config.EmailFrom, []string{email}, []byte(msg))
		if err != nil {
			log.Printf("[PASSWORD_RESET] Failed to send email to %s: %v", email, err)
		} else {
			log.Printf("[PASSWORD_RESET] Reset email sent to %s", email)
		}

		c.JSON(http.StatusOK, gin.H{"success": true, "message": "If an account exists with this username, a reset link will be sent to the registered email."})
	})

	// Password Reset Page
	r.GET("/reset_password", func(c *gin.Context) {
		token := c.Query("token")
		if token == "" {
			c.HTML(http.StatusBadRequest, "login.html", gin.H{"error": "Invalid reset link"})
			return
		}

		// Verify token
		doc, err := firestoreClient.Collection("password_resets").Doc(token).Get(context.Background())
		if err != nil || !doc.Exists() {
			c.HTML(http.StatusBadRequest, "login.html", gin.H{"error": "Invalid or expired reset link"})
			return
		}

		data := doc.Data()
		expiresAt, _ := data["expires_at"].(time.Time)
		used, _ := data["used"].(bool)

		if used || time.Now().After(expiresAt) {
			c.HTML(http.StatusBadRequest, "login.html", gin.H{"error": "This reset link has expired. Please request a new one."})
			return
		}

		// Show reset form (using login template with reset mode)
		c.HTML(http.StatusOK, "login.html", gin.H{
			"reset_mode":  true,
			"reset_token": token,
		})
	})

	// Password Reset Submit
	r.POST("/reset_password", func(c *gin.Context) {
		token := c.PostForm("token")
		newPassword := c.PostForm("new_password")
		confirmPassword := c.PostForm("confirm_password")

		if token == "" || newPassword == "" {
			c.HTML(http.StatusBadRequest, "login.html", gin.H{"error": "All fields are required", "reset_mode": true, "reset_token": token})
			return
		}

		if newPassword != confirmPassword {
			c.HTML(http.StatusBadRequest, "login.html", gin.H{"error": "Passwords do not match", "reset_mode": true, "reset_token": token})
			return
		}

		if len(newPassword) < 6 {
			c.HTML(http.StatusBadRequest, "login.html", gin.H{"error": "Password must be at least 6 characters", "reset_mode": true, "reset_token": token})
			return
		}

		// Verify token
		doc, err := firestoreClient.Collection("password_resets").Doc(token).Get(context.Background())
		if err != nil || !doc.Exists() {
			c.HTML(http.StatusBadRequest, "login.html", gin.H{"error": "Invalid reset link"})
			return
		}

		data := doc.Data()
		username := fmt.Sprint(data["username"])
		expiresAt, _ := data["expires_at"].(time.Time)
		used, _ := data["used"].(bool)

		if used || time.Now().After(expiresAt) {
			c.HTML(http.StatusBadRequest, "login.html", gin.H{"error": "This reset link has expired"})
			return
		}

		// Hash new password
		hashedPassword, err := hashPassword(newPassword)
		if err != nil {
			c.HTML(http.StatusInternalServerError, "login.html", gin.H{"error": "System error. Please try again."})
			return
		}

		// Update user password
		_, err = firestoreClient.Collection("users").Doc(username).Update(context.Background(), []firestore.Update{
			{Path: "password", Value: hashedPassword},
		})
		if err != nil {
			c.HTML(http.StatusInternalServerError, "login.html", gin.H{"error": "Failed to update password"})
			return
		}

		// Mark token as used
		firestoreClient.Collection("password_resets").Doc(token).Update(context.Background(), []firestore.Update{
			{Path: "used", Value: true},
		})

		log.Printf("[PASSWORD_RESET] Password successfully reset for user: %s", username)
		c.HTML(http.StatusOK, "login.html", gin.H{"success": "Password reset successful! You can now login with your new password."})
	})

	// Email configuration update
	r.POST("/update_email_config", func(c *gin.Context) {
		session := sessions.Default(c)
		if session.Get("role") != "admin" {
			c.Redirect(http.StatusFound, "/login")
			return
		}

		emailEnabled := c.PostForm("email_enabled") == "on"
		smtpServer := c.PostForm("smtp_server")
		smtpPortStr := c.PostForm("smtp_port")
		emailFrom := c.PostForm("email_from")
		emailPassword := c.PostForm("email_password")

		smtpPort := 587
		if p, err := strconv.Atoi(smtpPortStr); err == nil {
			smtpPort = p
		}

		updates := map[string]interface{}{
			"email_enabled":  emailEnabled,
			"smtp_server":    smtpServer,
			"smtp_port":      smtpPort,
			"email_from":     emailFrom,
			"email_password": emailPassword,
		}

		firestoreClient.Collection("config").Doc("semester").Set(context.Background(), updates, firestore.MergeAll)
		c.Redirect(http.StatusFound, "/settings")
	})

	// Test email endpoint
	r.POST("/api/test_email", func(c *gin.Context) {
		var data struct {
			SMTPServer    string `json:"smtp_server"`
			SMTPPort      string `json:"smtp_port"`
			EmailFrom     string `json:"email_from"`
			EmailPassword string `json:"email_password"`
			ToEmail       string `json:"to_email"`
		}
		if err := c.BindJSON(&data); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid data"})
			return
		}

		// Compose email
		subject := "QR Attendance System - Test Email"
		body := `
		<html>
		<body style="font-family: Arial, sans-serif; padding: 20px;">
			<div style="max-width: 500px; margin: 0 auto; background: linear-gradient(135deg, #667eea, #764ba2); padding: 30px; border-radius: 15px; color: white;">
				<h1 style="margin: 0 0 20px 0;">✅ Email Test Successful!</h1>
				<p style="margin: 0;">Your email configuration is working correctly.</p>
				<hr style="border: none; border-top: 1px solid rgba(255,255,255,0.3); margin: 20px 0;">
				<p style="font-size: 0.9em; opacity: 0.8;">Chaitanya Engineering College<br>QR Attendance System</p>
			</div>
		</body>
		</html>`

		msg := "From: " + data.EmailFrom + "\r\n" +
			"To: " + data.ToEmail + "\r\n" +
			"Subject: " + subject + "\r\n" +
			"MIME-Version: 1.0\r\n" +
			"Content-Type: text/html; charset=UTF-8\r\n" +
			"\r\n" + body

		auth := smtp.PlainAuth("", data.EmailFrom, data.EmailPassword, data.SMTPServer)
		addr := data.SMTPServer + ":" + data.SMTPPort

		err := smtp.SendMail(addr, auth, data.EmailFrom, []string{data.ToEmail}, []byte(msg))
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"success": false, "message": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"success": true, "message": "Email sent successfully"})
	})

	// Attendance reminder API - get teachers who haven't taken attendance today
	r.GET("/api/attendance_reminders", func(c *gin.Context) {
		session := sessions.Default(c)
		if session.Get("role") != "admin" {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Not authorized"})
			return
		}

		today := time.Now().Format("2006-01-02")

		// Get all teachers with their timetable entries for today
		dayOfWeek := time.Now().Weekday().String()

		// Get all timetable entries for today
		timetableIter := firestoreClient.Collection("timetable").Where("day_of_week", "==", dayOfWeek).Documents(context.Background())
		teacherClasses := make(map[string][]map[string]string)
		for {
			doc, err := timetableIter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				continue
			}
			data := doc.Data()
			teacherID := fmt.Sprint(data["teacher_id"])
			subject := fmt.Sprint(data["subject"])
			branch := fmt.Sprint(data["branch"])
			timeSlot := fmt.Sprint(data["time_slot"])

			teacherClasses[teacherID] = append(teacherClasses[teacherID], map[string]string{
				"subject":   subject,
				"branch":    branch,
				"time_slot": timeSlot,
			})
		}

		// Check which teachers have sessions today
		sessionsIter := firestoreClient.Collection("sessions").Where("date", "==", today).Documents(context.Background())
		teachersWithSessions := make(map[string]bool)
		for {
			doc, err := sessionsIter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				continue
			}
			data := doc.Data()
			teacherID := fmt.Sprint(data["teacher_id"])
			teachersWithSessions[teacherID] = true
		}

		// Find teachers who have classes but no sessions
		var reminders []map[string]interface{}
		for teacherID, classes := range teacherClasses {
			if !teachersWithSessions[teacherID] {
				// Get teacher name
				teacherDoc, err := firestoreClient.Collection("teachers").Doc(teacherID).Get(context.Background())
				teacherName := teacherID
				email := ""
				if err == nil && teacherDoc.Exists() {
					if v := teacherDoc.Data()["name"]; v != nil {
						teacherName = fmt.Sprint(v)
					}
					if v := teacherDoc.Data()["email"]; v != nil {
						email = fmt.Sprint(v)
					}
				}

				reminders = append(reminders, map[string]interface{}{
					"teacher_id":   teacherID,
					"teacher_name": teacherName,
					"email":        email,
					"classes":      classes,
				})
			}
		}

		c.JSON(http.StatusOK, gin.H{"success": true, "reminders": reminders, "date": today})
	})

	// Send attendance reminders
	r.POST("/api/send_attendance_reminders", func(c *gin.Context) {
		session := sessions.Default(c)
		if session.Get("role") != "admin" {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Not authorized"})
			return
		}

		// Get email config
		config := getConfig()
		if !config.EmailEnabled || config.EmailFrom == "" {
			c.JSON(http.StatusOK, gin.H{"success": false, "message": "Email not configured. Go to Settings to set up email."})
			return
		}

		var data struct {
			TeacherIDs []string `json:"teacher_ids"`
		}
		if err := c.BindJSON(&data); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid data"})
			return
		}

		sentCount := 0
		for _, teacherID := range data.TeacherIDs {
			teacherDoc, err := firestoreClient.Collection("teachers").Doc(teacherID).Get(context.Background())
			if err != nil || !teacherDoc.Exists() {
				continue
			}

			email := ""
			teacherName := teacherID
			if v := teacherDoc.Data()["email"]; v != nil {
				email = fmt.Sprint(v)
			}
			if v := teacherDoc.Data()["name"]; v != nil {
				teacherName = fmt.Sprint(v)
			}

			if email == "" {
				continue
			}

			// Send reminder email
			subject := "Attendance Reminder - " + time.Now().Format("January 2, 2006")
			body := fmt.Sprintf(`
			<html>
			<body style="font-family: Arial, sans-serif; padding: 20px;">
				<div style="max-width: 500px; margin: 0 auto; background: #f8f9fa; padding: 30px; border-radius: 15px;">
					<h2 style="color: #667eea; margin: 0 0 20px 0;">📢 Attendance Reminder</h2>
					<p>Dear %s,</p>
					<p>This is a friendly reminder that you haven't taken attendance for your scheduled classes today.</p>
					<p>Please log in to the QR Attendance System and start your session to mark attendance.</p>
					<hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
					<p style="font-size: 0.9em; color: #666;">Chaitanya Engineering College<br>QR Attendance System</p>
				</div>
			</body>
			</html>`, teacherName)

			msg := "From: " + config.EmailFrom + "\r\n" +
				"To: " + email + "\r\n" +
				"Subject: " + subject + "\r\n" +
				"MIME-Version: 1.0\r\n" +
				"Content-Type: text/html; charset=UTF-8\r\n" +
				"\r\n" + body

			auth := smtp.PlainAuth("", config.EmailFrom, config.EmailPassword, config.SMTPServer)
			addr := fmt.Sprintf("%s:%d", config.SMTPServer, config.SMTPPort)

			if err := smtp.SendMail(addr, auth, config.EmailFrom, []string{email}, []byte(msg)); err == nil {
				sentCount++
			}
		}

		c.JSON(http.StatusOK, gin.H{"success": true, "sent_count": sentCount})
	})

	// ==================== CORRECTION REQUESTS SYSTEM ====================

	// Student: Submit correction request
	r.POST("/student/submit_correction", func(c *gin.Context) {
		session := sessions.Default(c)
		userID := session.Get("user_id")
		if userID == nil || session.Get("role") != "student" {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Not authorized"})
			return
		}
		studentID := userID.(string)

		// Get student details
		studentDoc, err := firestoreClient.Collection("students").Doc(studentID).Get(context.Background())
		studentName := studentID
		branch := ""
		if err == nil && studentDoc.Exists() {
			if v := studentDoc.Data()["name"]; v != nil {
				studentName = fmt.Sprint(v)
			}
			if v := studentDoc.Data()["branch"]; v != nil {
				branch = fmt.Sprint(v)
			}
		}

		// Parse form data
		subject := c.PostForm("subject")
		teacherID := c.PostForm("teacher_id")
		absentDate := c.PostForm("absent_date")
		reason := c.PostForm("reason")

		if subject == "" || absentDate == "" || reason == "" {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Subject, date and reason are required"})
			return
		}

		// Get teacher name
		teacherName := teacherID
		if teacherID != "" {
			teacherDoc, err := firestoreClient.Collection("teachers").Doc(teacherID).Get(context.Background())
			if err == nil && teacherDoc.Exists() {
				if v := teacherDoc.Data()["name"]; v != nil && fmt.Sprint(v) != "" {
					teacherName = fmt.Sprint(v)
				}
			}
		}

		// Handle file upload (optional proof)
		proofImg := ""
		file, header, err := c.Request.FormFile("proof")
		if err == nil && file != nil {
			defer file.Close()
			filename := fmt.Sprintf("%s_%d_%s", studentID, time.Now().Unix(), header.Filename)
			filepath := "static/proofs/" + filename
			os.MkdirAll("static/proofs", os.ModePerm)
			out, err := os.Create(filepath)
			if err == nil {
				defer out.Close()
				buf := make([]byte, header.Size)
				file.Read(buf)
				out.Write(buf)
				proofImg = filename
			}
		}

		// Create correction request
		correctionReq := map[string]interface{}{
			"student_id":      studentID,
			"student_name":    studentName,
			"roll":            studentID,
			"branch":          branch,
			"subject":         subject,
			"teacher_id":      teacherID,
			"teacher_name":    teacherName,
			"absent_date":     absentDate,
			"reason":          reason,
			"proof_img":       proofImg,
			"status":          "PENDING",
			"teacher_remarks": "",
			"created_at":      time.Now(),
			"updated_at":      time.Now(),
		}

		docRef, _, err := firestoreClient.Collection("correction_requests").Add(context.Background(), correctionReq)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Failed to submit request"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"success": true, "message": "Correction request submitted successfully", "request_id": docRef.ID})
	})

	// Student: Get their correction requests
	r.GET("/student/my_corrections", func(c *gin.Context) {
		session := sessions.Default(c)
		userID := session.Get("user_id")
		if userID == nil || session.Get("role") != "student" {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Not authorized"})
			return
		}
		studentID := userID.(string)
		log.Printf("[STUDENT CORRECTIONS] Fetching for student: %s", studentID)

		// Simple query without OrderBy to avoid composite index requirement
		iter := firestoreClient.Collection("correction_requests").Where("student_id", "==", studentID).Documents(context.Background())
		var requests []map[string]interface{}

		for {
			doc, err := iter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				log.Printf("[STUDENT CORRECTIONS] Error reading doc: %v", err)
				continue
			}
			data := doc.Data()
			data["id"] = doc.Ref.ID
			requests = append(requests, data)
		}

		if requests == nil {
			requests = []map[string]interface{}{}
		}

		log.Printf("[STUDENT CORRECTIONS] Found %d requests for student %s", len(requests), studentID)
		c.JSON(http.StatusOK, gin.H{"success": true, "requests": requests})
	})

	// Student: Refresh attendance data (called when returning to dashboard after marking attendance)
	r.GET("/student/refresh_attendance", func(c *gin.Context) {
		session := sessions.Default(c)
		userID := session.Get("user_id")
		if userID == nil || session.Get("role") != "student" {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Not authorized"})
			return
		}
		studentID := userID.(string)

		// Fetch attendance records
		records := []Attendance{}
		totalPresent := 0
		iter := firestoreClient.Collection("attendance").Where("roll", "==", studentID).Documents(context.Background())
		for {
			doc, err := iter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				break
			}
			var a Attendance
			doc.DataTo(&a)
			a.ID = doc.Ref.ID
			records = append(records, a)
			if a.Status == "PRESENT" {
				totalPresent++
			}
		}

		// Fetch config for working days calculation
		config := getConfig()
		now := time.Now()
		var semesterStart, semesterEnd time.Time
		remainingSemDays := 0
		workingDays := 0

		if config.StartDate != "" {
			semesterStart, _ = time.Parse("2006-01-02", config.StartDate)
		}
		if config.EndDate != "" {
			semesterEnd, _ = time.Parse("2006-01-02", config.EndDate)
		}

		// Fetch holidays
		holidays := make(map[string]bool)
		holidayIter := firestoreClient.Collection("holidays").Documents(context.Background())
		for {
			hDoc, err := holidayIter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				break
			}
			var h Holiday
			hDoc.DataTo(&h)
			holidays[h.Date] = true
		}

		// Calculate remaining semester days
		if !semesterEnd.IsZero() && now.Before(semesterEnd) {
			for d := now; !d.After(semesterEnd); d = d.AddDate(0, 0, 1) {
				dateStr := d.Format("2006-01-02")
				if d.Weekday() == time.Sunday || d.Weekday() == time.Saturday {
					continue
				}
				if holidays[dateStr] {
					continue
				}
				remainingSemDays++
			}
		}

		// Calculate total working days
		if !semesterStart.IsZero() {
			endCalc := now
			if !semesterEnd.IsZero() && now.After(semesterEnd) {
				endCalc = semesterEnd
			}
			for d := semesterStart; !d.After(endCalc); d = d.AddDate(0, 0, 1) {
				dateStr := d.Format("2006-01-02")
				if d.Weekday() == time.Sunday || d.Weekday() == time.Saturday {
					continue
				}
				if holidays[dateStr] {
					continue
				}
				workingDays++
			}
		}

		var percentage float64 = 0.0
		if workingDays > 0 {
			percentage = (float64(totalPresent) / float64(workingDays)) * 100
		}

		c.JSON(http.StatusOK, gin.H{
			"success":            true,
			"total_present":      totalPresent,
			"working_days":       workingDays,
			"remaining_sem_days": remainingSemDays,
			"percentage":         percentage,
			"records":            records,
		})
	})

	// Student: Get subjects for correction dropdown (from their attendance records)
	r.GET("/student/get_subjects", func(c *gin.Context) {
		session := sessions.Default(c)
		userID := session.Get("user_id")
		if userID == nil || session.Get("role") != "student" {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Not authorized"})
			return
		}
		studentID := userID.(string)

		// Get unique subjects from attendance records
		iter := firestoreClient.Collection("attendance").Where("roll", "==", studentID).Documents(context.Background())
		subjectMap := make(map[string]map[string]string) // subject -> {teacher_id, teacher_name}

		for {
			doc, err := iter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				continue
			}
			data := doc.Data()
			subject, _ := data["subject"].(string)
			teacherID, _ := data["teacher_id"].(string)
			if subject != "" && subjectMap[subject] == nil {
				teacherName := teacherID
				if teacherID != "" {
					teacherDoc, err := firestoreClient.Collection("teachers").Doc(teacherID).Get(context.Background())
					if err == nil && teacherDoc.Exists() {
						if v := teacherDoc.Data()["name"]; v != nil && fmt.Sprint(v) != "" {
							teacherName = fmt.Sprint(v)
						}
					}
				}
				subjectMap[subject] = map[string]string{
					"teacher_id":   teacherID,
					"teacher_name": teacherName,
				}
			}
		}

		// Also get subjects from sessions
		sessIter := firestoreClient.Collection("sessions").Documents(context.Background())
		for {
			doc, err := sessIter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				continue
			}
			data := doc.Data()
			subject, _ := data["subject"].(string)
			teacherID, _ := data["teacher_id"].(string)
			if subject != "" && subjectMap[subject] == nil {
				teacherName := teacherID
				if teacherID != "" {
					teacherDoc, err := firestoreClient.Collection("teachers").Doc(teacherID).Get(context.Background())
					if err == nil && teacherDoc.Exists() {
						if v := teacherDoc.Data()["name"]; v != nil && fmt.Sprint(v) != "" {
							teacherName = fmt.Sprint(v)
						}
					}
				}
				subjectMap[subject] = map[string]string{
					"teacher_id":   teacherID,
					"teacher_name": teacherName,
				}
			}
		}

		var subjects []map[string]string
		for subject, info := range subjectMap {
			subjects = append(subjects, map[string]string{
				"subject":      subject,
				"teacher_id":   info["teacher_id"],
				"teacher_name": info["teacher_name"],
			})
		}

		if subjects == nil {
			subjects = []map[string]string{}
		}

		c.JSON(http.StatusOK, gin.H{"success": true, "subjects": subjects})
	})

	// Teacher: Refresh attendance records (dynamic fetch)
	r.GET("/teacher/refresh_attendance", func(c *gin.Context) {
		session := sessions.Default(c)
		userID := session.Get("user_id")
		if userID == nil || session.Get("role") != "teacher" {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Not authorized"})
			return
		}
		teacherID := userID.(string)

		// Get filter parameters
		subject := c.Query("subject")
		branch := c.Query("branch")
		date := c.Query("date")

		records := []Attendance{}

		// Try to fetch by teacher_id first
		iter := firestoreClient.Collection("attendance").Where("teacher_id", "==", teacherID).Documents(context.Background())
		for {
			doc, err := iter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				log.Printf("[TEACHER REFRESH] Error fetching by teacher_id: %v", err)
				break
			}
			var a Attendance
			doc.DataTo(&a)
			a.ID = doc.Ref.ID

			// Apply filters in Go
			if subject != "" && a.Subject != subject {
				continue
			}
			if branch != "" && a.Branch != branch {
				continue
			}
			if date != "" && a.Date != date {
				continue
			}

			records = append(records, a)
		}

		// If no records found by teacher_id, also try fetching by subjects this teacher teaches
		if len(records) == 0 {
			log.Printf("[TEACHER REFRESH] No records by teacher_id, trying by subjects for: %s", teacherID)

			// Get subjects this teacher teaches
			subIter := firestoreClient.Collection("subjects").Where("teacher_id", "==", teacherID).Documents(context.Background())
			teacherSubjects := []string{}
			for {
				subDoc, err := subIter.Next()
				if err == iterator.Done {
					break
				}
				if err != nil {
					continue
				}
				if subName, ok := subDoc.Data()["name"].(string); ok {
					teacherSubjects = append(teacherSubjects, subName)
				}
			}

			// Fetch attendance for those subjects
			for _, subj := range teacherSubjects {
				if subject != "" && subj != subject {
					continue
				}
				attIter := firestoreClient.Collection("attendance").Where("subject", "==", subj).Documents(context.Background())
				for {
					doc, err := attIter.Next()
					if err == iterator.Done {
						break
					}
					if err != nil {
						continue
					}
					var a Attendance
					doc.DataTo(&a)
					a.ID = doc.Ref.ID

					// Apply filters
					if branch != "" && a.Branch != branch {
						continue
					}
					if date != "" && a.Date != date {
						continue
					}

					records = append(records, a)
				}
			}
		}

		// Sort by timestamp descending
		sort.Slice(records, func(i, j int) bool {
			return records[i].Timestamp.After(records[j].Timestamp)
		})

		log.Printf("[TEACHER REFRESH] Found %d records for teacher %s", len(records), teacherID)

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"records": records,
		})
	})

	// Teacher: Get correction requests for their subjects
	r.GET("/teacher/correction_requests", func(c *gin.Context) {
		session := sessions.Default(c)
		userID := session.Get("user_id")
		if userID == nil || session.Get("role") != "teacher" {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Not authorized"})
			return
		}
		teacherID := userID.(string)
		log.Printf("[TEACHER CORRECTIONS] Fetching for teacher: %s", teacherID)

		// Simple query without OrderBy to avoid composite index requirement
		iter := firestoreClient.Collection("correction_requests").Where("teacher_id", "==", teacherID).Documents(context.Background())
		var requests []map[string]interface{}

		for {
			doc, err := iter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				log.Printf("[TEACHER CORRECTIONS] Error reading doc: %v", err)
				continue
			}
			data := doc.Data()
			data["id"] = doc.Ref.ID
			// Format created_at for display
			if createdAt, ok := data["created_at"].(time.Time); ok {
				data["created_at_display"] = createdAt.Format("02 Jan 2006, 15:04")
			}
			requests = append(requests, data)
		}

		if requests == nil {
			requests = []map[string]interface{}{}
		}

		log.Printf("[TEACHER CORRECTIONS] Found %d requests for teacher %s", len(requests), teacherID)
		c.JSON(http.StatusOK, gin.H{"success": true, "requests": requests})
	})

	// Teacher: Handle correction request (approve/reject)
	r.POST("/teacher/handle_correction", func(c *gin.Context) {
		session := sessions.Default(c)
		userID := session.Get("user_id")
		if userID == nil || session.Get("role") != "teacher" {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Not authorized"})
			return
		}
		teacherID := userID.(string)

		var data struct {
			RequestID string `json:"request_id"`
			Action    string `json:"action"` // APPROVE or REJECT
			Remarks   string `json:"remarks"`
		}
		if err := c.BindJSON(&data); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid data"})
			return
		}

		// Get the correction request
		docRef := firestoreClient.Collection("correction_requests").Doc(data.RequestID)
		doc, err := docRef.Get(context.Background())
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "message": "Request not found"})
			return
		}

		reqData := doc.Data()
		// Verify this request belongs to this teacher
		if reqData["teacher_id"] != teacherID {
			c.JSON(http.StatusForbidden, gin.H{"success": false, "message": "Not authorized to handle this request"})
			return
		}

		// Update the request
		status := "REJECTED"
		if data.Action == "APPROVE" {
			status = "APPROVED"
		}

		_, err = docRef.Update(context.Background(), []firestore.Update{
			{Path: "status", Value: status},
			{Path: "teacher_remarks", Value: data.Remarks},
			{Path: "updated_at", Value: time.Now()},
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Failed to update request"})
			return
		}

		// If approved, UPDATE the existing absent attendance record to present
		if status == "APPROVED" {
			studentID := fmt.Sprint(reqData["student_id"])
			subject := fmt.Sprint(reqData["subject"])
			absentDate := fmt.Sprint(reqData["absent_date"])

			// Find the existing absent attendance record for this student, subject, and date
			iter := firestoreClient.Collection("attendance").
				Where("roll", "==", studentID).
				Where("subject", "==", subject).
				Where("date", "==", absentDate).
				Documents(context.Background())

			updated := false
			for {
				doc, err := iter.Next()
				if err == iterator.Done {
					break
				}
				if err != nil {
					log.Printf("Error iterating attendance: %v", err)
					continue
				}

				// Update this record to Present
				_, err = doc.Ref.Update(context.Background(), []firestore.Update{
					{Path: "status", Value: "Present"},
					{Path: "time", Value: "Corrected"},
					{Path: "is_correction", Value: true},
					{Path: "correction_id", Value: data.RequestID},
					{Path: "corrected_at", Value: time.Now()},
				})
				if err != nil {
					log.Printf("Error updating attendance record: %v", err)
				} else {
					log.Printf("[CORRECTION] Updated attendance for %s, %s on %s to Present", studentID, subject, absentDate)
					updated = true
				}
			}

			if !updated {
				log.Printf("[CORRECTION] No existing attendance record found for %s, %s on %s", studentID, subject, absentDate)
			}
		}

		c.JSON(http.StatusOK, gin.H{"success": true, "message": "Request " + status + " successfully"})
	})

	// Admin: Get all correction requests
	r.GET("/admin/corrections", func(c *gin.Context) {
		session := sessions.Default(c)
		if session.Get("role") != "admin" {
			c.Redirect(http.StatusFound, "/login")
			return
		}

		// Get pending requests
		pendingIter := firestoreClient.Collection("correction_requests").Where("status", "==", "PENDING").OrderBy("created_at", firestore.Desc).Documents(context.Background())
		var pending []map[string]interface{}
		for {
			doc, err := pendingIter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				continue
			}
			data := doc.Data()
			data["ID"] = doc.Ref.ID
			if createdAt, ok := data["created_at"].(time.Time); ok {
				data["Timestamp"] = createdAt.Format("02 Jan 2006, 15:04")
			}
			data["StudentName"] = data["student_name"]
			data["Roll"] = data["roll"]
			data["Reason"] = data["reason"]
			data["ProofImg"] = data["proof_img"]
			data["Subject"] = data["subject"]
			data["TeacherName"] = data["teacher_name"]
			data["AbsentDate"] = data["absent_date"]
			pending = append(pending, data)
		}

		// Get history (approved/rejected)
		historyIter := firestoreClient.Collection("correction_requests").Where("status", "in", []string{"APPROVED", "REJECTED"}).OrderBy("updated_at", firestore.Desc).Limit(50).Documents(context.Background())
		var history []map[string]interface{}
		for {
			doc, err := historyIter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				continue
			}
			data := doc.Data()
			data["ID"] = doc.Ref.ID
			data["Roll"] = data["roll"]
			data["Reason"] = data["reason"]
			data["Status"] = data["status"]
			data["TeacherRemarks"] = data["teacher_remarks"]
			data["Subject"] = data["subject"]
			data["TeacherName"] = data["teacher_name"]
			history = append(history, data)
		}

		if pending == nil {
			pending = []map[string]interface{}{}
		}
		if history == nil {
			history = []map[string]interface{}{}
		}

		c.HTML(http.StatusOK, "admin_corrections.html", gin.H{"pending": pending, "history": history})
	})

	// Reports
	r.GET("/reports", func(c *gin.Context) {
		files, _ := filepath.Glob("static/reports/*.csv")
		names := []string{}
		for _, f := range files {
			names = append(names, filepath.Base(f))
		}
		c.HTML(http.StatusOK, "reports.html", gin.H{"reports": names})
	})
	r.GET("/api/generate_report", func(c *gin.Context) {
		// Mock generation
		fname := fmt.Sprintf("report_%s.csv", time.Now().Format("20060102_150405"))
		f, _ := os.Create("static/reports/" + fname)
		f.WriteString("Roll,Name,Status\n")
		f.Close()
		c.JSON(http.StatusOK, gin.H{"success": true})
	})

	// SMS Logs
	r.GET("/sms_logs", func(c *gin.Context) {
		c.HTML(http.StatusOK, "sms_logs.html", gin.H{"logs": []SMSLog{}})
	})

	// Analytics
	r.GET("/analytics", func(c *gin.Context) {
		c.HTML(http.StatusOK, "analytics.html", gin.H{})
	})

	r.GET("/export_csv", func(c *gin.Context) {
		session := sessions.Default(c)
		role := session.Get("role")
		if role != "admin" && role != "teacher" {
			c.String(http.StatusUnauthorized, "Unauthorized")
			return
		}

		// Get filter parameters
		branch := c.Query("branch")
		subject := c.Query("subject")
		dateFrom := c.Query("date_from")
		dateTo := c.Query("date_to")
		exportType := c.Query("type") // "attendance" or "students"

		ctx := context.Background()
		var buf bytes.Buffer
		writer := csv.NewWriter(&buf)

		if exportType == "students" {
			// Export students list
			writer.Write([]string{"Roll No", "Name", "Branch", "Email", "Parent Phone"})

			query := firestoreClient.Collection("students").Documents(ctx)
			if branch != "" {
				query = firestoreClient.Collection("students").Where("branch", "==", branch).Documents(ctx)
			}

			for {
				doc, err := query.Next()
				if err == iterator.Done {
					break
				}
				if err != nil {
					continue
				}
				data := doc.Data()
				rollNo := doc.Ref.ID
				if r, ok := data["roll"].(string); ok && r != "" {
					rollNo = r
				}
				name := fmt.Sprint(data["name"])
				studentBranch := fmt.Sprint(data["branch"])
				email := fmt.Sprint(data["email"])
				parentPhone := fmt.Sprint(data["parent_phone"])

				writer.Write([]string{rollNo, name, studentBranch, email, parentPhone})
			}
		} else {
			// Export attendance records
			writer.Write([]string{"Roll No", "Name", "Subject", "Branch", "Date", "Time", "Status"})

			// Build query
			query := firestoreClient.Collection("attendance").OrderBy("date", firestore.Desc)

			// Apply filters if teacher
			if role == "teacher" {
				teacherID := session.Get("user_id").(string)
				query = firestoreClient.Collection("attendance").Where("teacher_id", "==", teacherID).OrderBy("date", firestore.Desc)
			}

			iter := query.Limit(5000).Documents(ctx)

			for {
				doc, err := iter.Next()
				if err == iterator.Done {
					break
				}
				if err != nil {
					continue
				}
				data := doc.Data()

				// Apply filters
				recordBranch := fmt.Sprint(data["branch"])
				recordSubject := fmt.Sprint(data["subject"])
				recordDate := fmt.Sprint(data["date"])

				if branch != "" && recordBranch != branch {
					continue
				}
				if subject != "" && recordSubject != subject {
					continue
				}
				if dateFrom != "" && recordDate < dateFrom {
					continue
				}
				if dateTo != "" && recordDate > dateTo {
					continue
				}

				roll := fmt.Sprint(data["roll"])
				name := fmt.Sprint(data["name"])
				timeStr := fmt.Sprint(data["time"])
				status := fmt.Sprint(data["status"])

				writer.Write([]string{roll, name, recordSubject, recordBranch, recordDate, timeStr, status})
			}
		}

		writer.Flush()

		// Generate filename
		filename := fmt.Sprintf("attendance_export_%s.csv", time.Now().Format("2006-01-02_150405"))
		if exportType == "students" {
			filename = fmt.Sprintf("students_export_%s.csv", time.Now().Format("2006-01-02_150405"))
		}

		c.Header("Content-Type", "text/csv")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
		c.Data(http.StatusOK, "text/csv", buf.Bytes())
	})

	// Scan - This is for STUDENTS to mark attendance
	r.GET("/scan", func(c *gin.Context) {
		token := c.Query("token")
		// Find the session by token
		iter := firestoreClient.Collection("sessions").Where("qr_token", "==", token).Documents(context.Background())
		doc, err := iter.Next()
		if err != nil {
			c.HTML(http.StatusOK, "scan.html", gin.H{"is_expired": true})
			return
		}
		data := doc.Data()
		// Check if session is finalized or expired
		isFinalized, _ := data["is_finalized"].(bool)
		endTime, _ := data["end_time"].(float64)
		now := float64(time.Now().Unix())
		if isFinalized || now > endTime {
			c.HTML(http.StatusOK, "scan.html", gin.H{"is_expired": true})
			return
		}
		c.HTML(http.StatusOK, "scan.html", gin.H{
			"token":      token,
			"is_expired": false,
			"subject":    data["subject"],
			"branch":     data["branch"],
			"exp":        int64(endTime),
		})
	})

	// QR Display - This is for TEACHERS to show QR code
	r.GET("/qr_display", func(c *gin.Context) {
		token := c.Query("token")
		// Find the session by token
		iter := firestoreClient.Collection("sessions").Where("qr_token", "==", token).Documents(context.Background())
		doc, err := iter.Next()
		if err != nil {
			c.Redirect(http.StatusFound, "/teacher")
			return
		}
		data := doc.Data()
		endTime, _ := data["end_time"].(float64)
		startTimeStr, _ := data["time"].(string)
		classType, _ := data["class_type"].(string)
		c.HTML(http.StatusOK, "qr_display.html", gin.H{
			"token":      token,
			"session_id": doc.Ref.ID,
			"subject":    data["subject"],
			"branch":     data["branch"],
			"class_type": classType,
			"start_time": startTimeStr,
			"end_time":   int64(endTime),
		})
	})

	r.GET("/get_qr_img/:token", func(c *gin.Context) {
		token := c.Param("token")
		// In production use proper host
		url := fmt.Sprintf("http://%s/scan?token=%s", c.Request.Host, token)

		// Generate QR code with higher error correction for logo overlay
		qr, err := qrcode.New(url, qrcode.High)
		if err != nil {
			// Fallback to simple QR
			png, _ := qrcode.Encode(url, qrcode.Medium, 256)
			c.Data(http.StatusOK, "image/png", png)
			return
		}
		qr.DisableBorder = false

		// Generate QR image
		qrImage := qr.Image(300)

		// Try to load college logo
		logoPath := filepath.Join("static", "images", "cec_logo.png")
		logoFile, err := os.Open(logoPath)
		if err == nil {
			defer logoFile.Close()
			logoImg, _, err := image.Decode(logoFile)
			if err == nil {
				// Create a new image with logo in center
				bounds := qrImage.Bounds()
				result := image.NewRGBA(bounds)
				draw.Draw(result, bounds, qrImage, image.Point{}, draw.Src)

				// Calculate logo position (center, scaled to ~20% of QR)
				logoSize := bounds.Dx() / 5
				logoBounds := logoImg.Bounds()

				// Scale logo
				scaledLogo := image.NewRGBA(image.Rect(0, 0, logoSize, logoSize))
				for y := 0; y < logoSize; y++ {
					for x := 0; x < logoSize; x++ {
						srcX := x * logoBounds.Dx() / logoSize
						srcY := y * logoBounds.Dy() / logoSize
						scaledLogo.Set(x, y, logoImg.At(srcX, srcY))
					}
				}

				// Center position
				logoX := (bounds.Dx() - logoSize) / 2
				logoY := (bounds.Dy() - logoSize) / 2

				// Draw scaled logo
				draw.Draw(result, image.Rect(logoX, logoY, logoX+logoSize, logoY+logoSize),
					scaledLogo, image.Point{}, draw.Over)

				// Encode to PNG
				var buf bytes.Buffer
				png.Encode(&buf, result)
				c.Data(http.StatusOK, "image/png", buf.Bytes())
				return
			}
		}

		// Fallback: QR without logo
		var buf bytes.Buffer
		png.Encode(&buf, qrImage)
		c.Data(http.StatusOK, "image/png", buf.Bytes())
	})

	r.POST("/mark_session_attendance", func(c *gin.Context) {
		var data struct {
			Roll      string  `json:"roll"`
			Name      string  `json:"name"`
			Token     string  `json:"token"`
			DeviceID  string  `json:"device_id"`
			Latitude  float64 `json:"latitude"`
			Longitude float64 `json:"longitude"`
		}
		if err := c.BindJSON(&data); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid data"})
			return
		}

		// Find the session by token
		iter := firestoreClient.Collection("sessions").Where("qr_token", "==", data.Token).Documents(context.Background())
		sessionDoc, err := iter.Next()
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid or expired QR code"})
			return
		}

		sessionData := sessionDoc.Data()
		sessionID := sessionDoc.Ref.ID

		// Check if session is finalized or expired
		isFinalized, _ := sessionData["is_finalized"].(bool)
		endTime, _ := sessionData["end_time"].(float64)
		now := float64(time.Now().Unix())
		if isFinalized || now > endTime {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "This session has expired"})
			return
		}

		// Geofencing validation
		config := getConfig()
		if config.GeoEnabled && config.CollegeLat != 0 && config.CollegeLng != 0 {
			if data.Latitude == 0 && data.Longitude == 0 {
				c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Location access is required. Please enable location services and try again."})
				return
			}

			distance := haversineDistance(config.CollegeLat, config.CollegeLng, data.Latitude, data.Longitude)
			if distance > config.GeoRadius {
				log.Printf("[GEOFENCE] Denied: Student %s is %.0fm away (limit: %.0fm)", data.Roll, distance, config.GeoRadius)
				c.JSON(http.StatusBadRequest, gin.H{
					"success": false,
					"message": fmt.Sprintf("You must be within %.0fm of the college to mark attendance. You are currently %.0fm away.", config.GeoRadius, distance),
				})
				return
			}
			log.Printf("[GEOFENCE] Allowed: Student %s is %.0fm away (limit: %.0fm)", data.Roll, distance, config.GeoRadius)
		}

		// Check if this DEVICE already marked attendance for this session (prevents proxy)
		if data.DeviceID != "" {
			deviceIter := firestoreClient.Collection("attendance").
				Where("session_id", "==", sessionID).
				Where("device_id", "==", data.DeviceID).
				Documents(context.Background())
			deviceDoc, _ := deviceIter.Next()
			if deviceDoc != nil {
				c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "This device has already submitted attendance for this session!"})
				return
			}
		}

		// Check if roll number already marked for this session
		existingIter := firestoreClient.Collection("attendance").
			Where("session_id", "==", sessionID).
			Where("roll", "==", data.Roll).
			Documents(context.Background())
		existingDoc, _ := existingIter.Next()
		if existingDoc != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "This roll number has already marked attendance!"})
			return
		}

		// Mark attendance
		subject, _ := sessionData["subject"].(string)
		branch, _ := sessionData["branch"].(string)
		teacherID, _ := sessionData["teacher_id"].(string)
		date, _ := sessionData["date"].(string)

		currentTime := time.Now()

		attendanceRecord := map[string]interface{}{
			"session_id": sessionID,
			"roll":       data.Roll,
			"name":       data.Name,
			"subject":    subject,
			"branch":     branch,
			"teacher_id": teacherID,
			"date":       date,
			"time":       currentTime.Format("15:04:05"),
			"timestamp":  currentTime,
			"status":     "PRESENT",
			"device_id":  data.DeviceID,
			"latitude":   data.Latitude,
			"longitude":  data.Longitude,
		}

		_, _, err = firestoreClient.Collection("attendance").Add(context.Background(), attendanceRecord)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Failed to mark attendance"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"success": true, "message": "Attendance marked successfully!"})
	})

	// ==================== TEACHER ATTENDANCE (PERMANENT QR) ====================

	// 1. Permanent QR Entry Point - PUBLIC (no login redirect)
	r.GET("/teacher-attendance", func(c *gin.Context) {
		session := sessions.Default(c)
		userID := session.Get("user_id")
		role := session.Get("role")

		today := time.Now().Format("2006-01-02")

		// If logged in as teacher, show attendance marking page
		if userID != nil && role == "teacher" {
			teacherID := userID.(string)
			// Check if attendance already marked for today
			iter := firestoreClient.Collection("teacher_attendance").
				Where("teacher_id", "==", teacherID).
				Where("date", "==", today).
				Documents(context.Background())

			alreadyMarked := false
			doc, err := iter.Next()
			if err == nil && doc != nil {
				alreadyMarked = true
			}

			// Get teacher name
			teacherName := teacherID
			tDoc, _ := firestoreClient.Collection("teachers").Doc(teacherID).Get(context.Background())
			if tDoc != nil && tDoc.Exists() {
				if v := tDoc.Data()["name"]; v != nil {
					teacherName = fmt.Sprint(v)
				}
			}

			c.HTML(http.StatusOK, "teacher_attendance_mark.html", gin.H{
				"teacher_id":     teacherID,
				"teacher_name":   teacherName,
				"date":           today,
				"already_marked": alreadyMarked,
				"logged_in":      true,
			})
			return
		}

		// Not logged in - show public page with login form
		c.HTML(http.StatusOK, "teacher_attendance_mark.html", gin.H{
			"date":      today,
			"logged_in": false,
		})
	})

	// API: Teacher Login + Mark Attendance (for QR code flow)
	r.POST("/api/teacher-login-mark", func(c *gin.Context) {
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid request"})
			return
		}

		// Verify credentials
		doc, err := firestoreClient.Collection("users").Doc(req.Username).Get(context.Background())
		if err != nil || !doc.Exists() {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Invalid username or password"})
			return
		}

		var user User
		if err := doc.DataTo(&user); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "System error"})
			return
		}

		if !checkPasswordHash(req.Password, user.Password) {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Invalid username or password"})
			return
		}

		if user.Role != "teacher" {
			c.JSON(http.StatusForbidden, gin.H{"success": false, "message": "Only teachers can use this feature"})
			return
		}

		teacherID := user.Username
		today := time.Now().Format("2006-01-02")

		// Check if already marked
		iter := firestoreClient.Collection("teacher_attendance").
			Where("teacher_id", "==", teacherID).
			Where("date", "==", today).
			Documents(context.Background())

		existingDoc, _ := iter.Next()
		if existingDoc != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Attendance already marked for today"})
			return
		}

		// Get teacher name
		teacherName := teacherID
		tDoc, _ := firestoreClient.Collection("teachers").Doc(teacherID).Get(context.Background())
		if tDoc != nil && tDoc.Exists() {
			if v := tDoc.Data()["name"]; v != nil {
				teacherName = fmt.Sprint(v)
			}
		}

		// Mark attendance
		now := time.Now()
		record := TeacherAttendance{
			TeacherID: teacherID,
			Name:      teacherName,
			Date:      today,
			Time:      now.Format("15:04:05"),
			Status:    "PRESENT",
			Timestamp: now,
		}

		_, _, err = firestoreClient.Collection("teacher_attendance").Add(context.Background(), record)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Failed to save attendance"})
			return
		}

		// Set session for future use
		session := sessions.Default(c)
		session.Set("user_id", teacherID)
		session.Set("username", teacherID)
		session.Set("role", "teacher")
		session.Save()

		c.JSON(http.StatusOK, gin.H{"success": true, "message": "Attendance marked successfully!"})
	})

	// API: Teacher Register + Mark Attendance (for QR code flow - new teachers)
	r.POST("/api/teacher-register-mark", func(c *gin.Context) {
		var req struct {
			Username string `json:"username"`
			FullName string `json:"full_name"`
			Email    string `json:"email"`
			Phone    string `json:"phone"`
			Password string `json:"password"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid request"})
			return
		}

		// Validate required fields
		if req.Username == "" || req.FullName == "" || req.Email == "" || req.Password == "" {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Username, full name, email, and password are required"})
			return
		}

		// Validate password length
		if len(req.Password) < 6 {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Password must be at least 6 characters"})
			return
		}

		// Check if user already exists
		_, err := firestoreClient.Collection("users").Doc(req.Username).Get(context.Background())
		if err == nil {
			c.JSON(http.StatusConflict, gin.H{"success": false, "message": "Teacher ID already exists. Please login instead."})
			return
		}

		// Hash password
		hashedPassword, err := hashPassword(req.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "System error"})
			return
		}

		// Create user in users collection
		user := User{
			Username:  req.Username,
			Password:  hashedPassword,
			Role:      "teacher",
			Email:     req.Email,
			CreatedAt: time.Now(),
		}
		_, err = firestoreClient.Collection("users").Doc(req.Username).Set(context.Background(), user)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Failed to create account"})
			return
		}

		// Create entry in teachers collection
		teacherData := map[string]interface{}{
			"name":       req.FullName,
			"email":      req.Email,
			"phone":      req.Phone,
			"created_at": time.Now(),
		}
		_, err = firestoreClient.Collection("teachers").Doc(req.Username).Set(context.Background(), teacherData)
		if err != nil {
			log.Printf("Error creating teacher record: %v", err)
			// Continue anyway - user account was created
		}

		// Mark attendance
		today := time.Now().Format("2006-01-02")
		now := time.Now()
		record := TeacherAttendance{
			TeacherID: req.Username,
			Name:      req.FullName,
			Date:      today,
			Time:      now.Format("15:04:05"),
			Status:    "PRESENT",
			Timestamp: now,
		}

		_, _, err = firestoreClient.Collection("teacher_attendance").Add(context.Background(), record)
		if err != nil {
			log.Printf("Error marking attendance after registration: %v", err)
			// Don't fail - account was created successfully
		}

		// Set session
		session := sessions.Default(c)
		session.Set("user_id", req.Username)
		session.Set("username", req.Username)
		session.Set("role", "teacher")
		session.Save()

		c.JSON(http.StatusOK, gin.H{"success": true, "message": "Registration successful! Attendance marked."})
	})

	// 2. Mark Attendance Action
	r.POST("/teacher/mark-attendance", func(c *gin.Context) {
		session := sessions.Default(c)
		userID := session.Get("user_id")
		if userID == nil || session.Get("role") != "teacher" {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Unauthorized"})
			return
		}
		teacherID := userID.(string)

		// Double check if already marked
		today := time.Now().Format("2006-01-02")
		iter := firestoreClient.Collection("teacher_attendance").
			Where("teacher_id", "==", teacherID).
			Where("date", "==", today).
			Documents(context.Background())

		doc, err := iter.Next()
		if err == nil && doc != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Attendance already marked for today."})
			return
		}

		// Get Teacher Name
		teacherName := teacherID
		tDoc, err := firestoreClient.Collection("teachers").Doc(teacherID).Get(context.Background())
		if err == nil && tDoc.Exists() {
			if v := tDoc.Data()["name"]; v != nil {
				teacherName = fmt.Sprint(v)
			}
		}

		now := time.Now()
		record := TeacherAttendance{
			TeacherID: teacherID,
			Name:      teacherName,
			Date:      today,
			Time:      now.Format("15:04:05"),
			Status:    "PRESENT",
			Timestamp: now,
		}

		_, _, err = firestoreClient.Collection("teacher_attendance").Add(context.Background(), record)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Database error"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"success": true, "message": "Attendance marked successfully!"})
	})

	// 3. Raise Issue
	r.POST("/teacher/raise-issue", func(c *gin.Context) {
		session := sessions.Default(c)
		userID := session.Get("user_id")
		if userID == nil || session.Get("role") != "teacher" {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Unauthorized"})
			return
		}
		teacherID := userID.(string)

		var req struct {
			Date     string `json:"date"`
			Reason   string `json:"reason"`
			ProofURL string `json:"proof_url"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid data"})
			return
		}

		// Get Teacher Name
		teacherName := teacherID
		tDoc, err := firestoreClient.Collection("teachers").Doc(teacherID).Get(context.Background())
		if err == nil && tDoc.Exists() {
			if v := tDoc.Data()["name"]; v != nil {
				teacherName = fmt.Sprint(v)
			}
		}

		issue := TeacherIssue{
			TeacherID: teacherID,
			Name:      teacherName,
			Date:      req.Date,
			Reason:    req.Reason,
			ProofURL:  req.ProofURL,
			Status:    "PENDING",
			CreatedAt: time.Now(),
		}

		_, _, err = firestoreClient.Collection("teacher_issues").Add(context.Background(), issue)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Database error"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"success": true, "message": "Issue submitted successfully!"})
	})

	// 4. Submit Permission/Leave Request
	r.POST("/teacher/permission-request", func(c *gin.Context) {
		session := sessions.Default(c)
		userID := session.Get("user_id")
		if userID == nil || session.Get("role") != "teacher" {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Unauthorized"})
			return
		}
		teacherID := userID.(string)

		var req struct {
			Title     string `json:"title"`
			StartDate string `json:"start_date"`
			EndDate   string `json:"end_date"`
			TimeFrom  string `json:"time_from"`
			TimeTo    string `json:"time_to"`
			Reason    string `json:"reason"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid data"})
			return
		}

		if req.Title == "" || req.StartDate == "" || req.Reason == "" {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Title, start date, and reason are required"})
			return
		}

		// Get Teacher Name
		teacherName := teacherID
		tDoc, err := firestoreClient.Collection("teachers").Doc(teacherID).Get(context.Background())
		if err == nil && tDoc.Exists() {
			if v := tDoc.Data()["name"]; v != nil {
				teacherName = fmt.Sprint(v)
			}
		}

		now := time.Now()
		permReq := PermissionRequest{
			TeacherID:   teacherID,
			TeacherName: teacherName,
			Title:       req.Title,
			StartDate:   req.StartDate,
			EndDate:     req.EndDate,
			TimeFrom:    req.TimeFrom,
			TimeTo:      req.TimeTo,
			Reason:      req.Reason,
			Status:      "PENDING",
			CreatedAt:   now,
			UpdatedAt:   now,
		}

		_, _, err = firestoreClient.Collection("permission_requests").Add(context.Background(), permReq)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Database error"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"success": true, "message": "Permission request submitted successfully! Admin will review it."})
	})

	// 5. Admin: Teacher Attendance Manager
	r.GET("/admin/teacher-attendance", func(c *gin.Context) {
		session := sessions.Default(c)
		if session.Get("role") != "admin" {
			c.Redirect(http.StatusFound, "/login")
			return
		}

		// Fetch today's records
		today := time.Now().Format("2006-01-02")
		attIter := firestoreClient.Collection("teacher_attendance").Where("date", "==", today).Documents(context.Background())
		var attendance []TeacherAttendance
		for {
			doc, err := attIter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				continue
			}
			var a TeacherAttendance
			doc.DataTo(&a)
			a.ID = doc.Ref.ID
			attendance = append(attendance, a)
		}

		// Fetch Pending Issues
		issueIter := firestoreClient.Collection("teacher_issues").Where("status", "==", "PENDING").Documents(context.Background())
		var issues []TeacherIssue
		for {
			doc, err := issueIter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				continue
			}
			var i TeacherIssue
			doc.DataTo(&i)
			i.ID = doc.Ref.ID
			issues = append(issues, i)
		}

		// History (Last 50) - Query descending
		// Note: Requires composite index if we mix Where & OrderBy on different fields.
		// For simplicity, just OrderBy timestamp and filter? Or just OrderBy timestamp.
		histIter := firestoreClient.Collection("teacher_attendance").OrderBy("timestamp", firestore.Desc).Limit(50).Documents(context.Background())
		var history []TeacherAttendance
		for {
			doc, err := histIter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				continue
			}
			var a TeacherAttendance
			doc.DataTo(&a)
			a.ID = doc.Ref.ID
			history = append(history, a)
		}

		// Fetch Pending Permission Requests
		permIter := firestoreClient.Collection("permission_requests").Where("status", "==", "PENDING").Documents(context.Background())
		var permissionRequests []PermissionRequest
		for {
			doc, err := permIter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				continue
			}
			var p PermissionRequest
			doc.DataTo(&p)
			p.ID = doc.Ref.ID
			permissionRequests = append(permissionRequests, p)
		}

		c.HTML(http.StatusOK, "admin_teacher_mgr.html", gin.H{
			"attendance":          attendance,
			"issues":              issues,
			"permission_requests": permissionRequests,
			"history":             history,
			"today":               today,
		})
	})

	// Generate QR Code for Teacher Attendance (Permanent)
	r.GET("/admin/teacher-qr", func(c *gin.Context) {
		// Build the target URL from request
		scheme := "https"
		host := c.Request.Host
		if strings.Contains(host, "localhost") || strings.Contains(host, "127.0.0.1") {
			scheme = "http"
		}
		// Check for X-Forwarded headers (ngrok/proxy)
		if fwdHost := c.GetHeader("X-Forwarded-Host"); fwdHost != "" {
			host = fwdHost
		}
		if fwdProto := c.GetHeader("X-Forwarded-Proto"); fwdProto != "" {
			scheme = fwdProto
		}

		targetURL := scheme + "://" + host + "/teacher-attendance"

		// Generate QR code
		png, err := qrcode.Encode(targetURL, qrcode.Medium, 300)
		if err != nil {
			c.String(http.StatusInternalServerError, "Failed to generate QR")
			return
		}

		c.Data(http.StatusOK, "image/png", png)
	})

	// 5. Admin: Handle Issue

	r.POST("/admin/teacher-issue", func(c *gin.Context) {
		session := sessions.Default(c)
		if session.Get("role") != "admin" {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Unauthorized"})
			return
		}
		var req struct {
			IssueID string `json:"issue_id"`
			Action  string `json:"action"` // APPROVE, REJECT
			Remarks string `json:"remarks"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid data"})
			return
		}

		status := "REJECTED"
		if req.Action == "APPROVE" {
			status = "APPROVED"
		}

		docRef := firestoreClient.Collection("teacher_issues").Doc(req.IssueID)
		_, err := docRef.Update(context.Background(), []firestore.Update{
			{Path: "status", Value: status},
			{Path: "admin_remarks", Value: req.Remarks},
		})

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Update failed"})
			return
		}

		// If approved, verify if we need to create an attendance record
		if status == "APPROVED" {
			// Fetch issue details
			doc, _ := docRef.Get(context.Background())
			var issue TeacherIssue
			doc.DataTo(&issue)

			// Check if attendance exists
			iter := firestoreClient.Collection("teacher_attendance").
				Where("teacher_id", "==", issue.TeacherID).
				Where("date", "==", issue.Date).
				Documents(context.Background())
			existingDoc, err := iter.Next()

			if existingDoc == nil || err != nil {
				// Create attendance record
				record := TeacherAttendance{
					TeacherID: issue.TeacherID,
					Name:      issue.Name,
					Date:      issue.Date,
					Time:      "Approved Request",
					Status:    "PRESENT", // Assuming approval means granting attendance
					Timestamp: time.Now(),
				}
				firestoreClient.Collection("teacher_attendance").Add(context.Background(), record)
			}
		}

		c.JSON(http.StatusOK, gin.H{"success": true})
	})

	// 6. Admin: Handle Permission Request (Approve/Reject)
	r.POST("/admin/permission-request", func(c *gin.Context) {
		session := sessions.Default(c)
		if session.Get("role") != "admin" {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Unauthorized"})
			return
		}
		var req struct {
			RequestID string `json:"request_id"`
			Action    string `json:"action"` // APPROVE, REJECT
			Remarks   string `json:"remarks"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid data"})
			return
		}

		status := "REJECTED"
		if req.Action == "APPROVE" {
			status = "APPROVED"
		}

		docRef := firestoreClient.Collection("permission_requests").Doc(req.RequestID)
		_, err := docRef.Update(context.Background(), []firestore.Update{
			{Path: "status", Value: status},
			{Path: "admin_remarks", Value: req.Remarks},
			{Path: "updated_at", Value: time.Now()},
		})

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Update failed"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"success": true, "message": "Permission request " + status})
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	r.Run(":" + port)
}
