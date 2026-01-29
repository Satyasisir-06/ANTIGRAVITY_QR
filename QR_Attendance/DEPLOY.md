# Deployment Guide - QR Attendance (Render - FREE, No Credit Card)

## Quick Deploy to Render

### Step 1: Go to Render
1. Visit **[render.com](https://render.com)**
2. Click **"Get Started for Free"**
3. **Sign up with GitHub**

### Step 2: Create Web Service
1. Click **"New +"** → **"Web Service"**
2. Connect your GitHub account if prompted
3. Select repository: `Satyasisir-06/ANTIGRAVITY_QR`
4. Configure:
   - **Name:** `qr-attendance`
   - **Root Directory:** `QR_Attendance`
   - **Runtime:** `Go`
   - **Build Command:** `go build -o main .`
   - **Start Command:** `./main`
5. Click **"Create Web Service"**

### Step 3: Add Environment Variable
1. Go to **Environment** tab
2. Add:
   - **Key:** `FIREBASE_CONFIG`
   - **Value:** Your firebase-credentials.json content (minified)
cd QR_Attendance
gcloud run deploy qr-attendance \
  --source . \
  --region asia-south1 \
  --allow-unauthenticated \
  --port 8080 \
  --set-env-vars="FIREBASE_API_KEY=your-key,PROJECT_ID=your-project-id"- ✅ 750 hours/month (enough for 24/7)
- ⚠️ Sleeps after 15 min inactivity (~30s wake time)

---

## Your URLs
- Render: `https://qr-attendance.onrender.com`
- Custom: `https://yourdomain.com`
