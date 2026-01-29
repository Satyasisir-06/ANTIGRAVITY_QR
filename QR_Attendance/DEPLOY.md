# Deployment Guide - QR Attendance (Google Cloud Run - FREE)

## Prerequisites
1. Google Cloud account (use same account as Firebase)
2. Google Cloud CLI installed
3. Docker (optional, Cloud Run can build from source)

---

## Quick Deploy to Cloud Run

### Step 1: Install Google Cloud CLI
Download from: https://cloud.google.com/sdk/docs/install

### Step 2: Login & Set Project
```bash
gcloud auth login
gcloud config set project YOUR_FIREBASE_PROJECT_ID
```

### Step 3: Enable APIs
```bash
gcloud services enable run.googleapis.com
gcloud services enable cloudbuild.googleapis.com
```

### Step 4: Deploy
```bash
cd QR_Attendance
gcloud run deploy qr-attendance \
  --source . \
  --region asia-south1 \
  --allow-unauthenticated \
  --port 8080
```

Cloud Run will build and deploy automatically!

---

## Add Custom Domain (Namecheap)

### In Cloud Console:
1. Go to [Cloud Run Console](https://console.cloud.google.com/run)
2. Select your service → **Domain Mappings** → **Add Mapping**
3. Verify domain ownership
4. Get the DNS records to add

### In Namecheap:
1. Advanced DNS → Add the records Cloud Run provides
2. Wait 5-30 minutes for DNS propagation

---

## Free Tier Limits

| Resource | Free/Month |
|----------|-----------|
| Requests | 2 million |
| CPU | 180,000 vCPU-seconds |
| Memory | 360,000 GB-seconds |
| Egress | 1 GB (NA) |

---

## Your URLs
- **Cloud Run URL:** `https://qr-attendance-xxxxx.run.app`
- **Custom Domain:** `https://yourdomain.com`
- **Teacher QR:** `https://yourdomain.com/teacher-attendance`
