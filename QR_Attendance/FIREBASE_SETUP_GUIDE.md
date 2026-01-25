# Firebase Setup Guide

## Step 1: Create Firebase Project (2 minutes)

1. Go to https://console.firebase.google.com
2. Click **"Add project"**
3. Name it: `QR-Attendance`
4. Disable Google Analytics (not needed)
5. Click **"Create project"**

## Step 2: Enable Firestore (1 minute)

1. In your project, click **"Firestore Database"** from left menu
2. Click **"Create database"**
3. Select **"Start in test mode"** (we'll secure it later)
4. Choose your region (select closest to you)
5. Click **"Enable"**

## Step 3: Enable Authentication (1 minute)

1. Click **"Authentication"** from left menu
2. Click **"Get started"**
3. Click **"Email/Password"**
4. Toggle **"Enable"**
5. Click **"Save"**

## Step 4: Get Service Account Key (IMPORTANT)

1. Click the **gear icon** (⚙️) → **"Project settings"**
2. Go to **"Service accounts"** tab
3. Click **"Generate new private key"**
4. Click **"Generate key"** (downloads a JSON file)
5. **SAVE THIS FILE** - you'll need it for deployment

## Step 5: For Vercel Deployment

You'll need to add the entire JSON file content as an environment variable:

1. Open the JSON file you downloaded
2. Copy ALL the contents
3. In Vercel:
   - Go to Settings → Environment Variables
   - Name: `FIREBASE_CONFIG`
   - Value: (paste the entire JSON)
   - Check all environments
   - Save

## For Local Testing

Save the JSON file as `firebase-credentials.json` in your project folder (don't commit it to git!)

---

## What This Gives You

✅ No DATABASE_URL issues
✅ No SQL schema to maintain
✅ Automatic scaling
✅ Real-time updates
✅ Built-in user authentication
✅ Works perfectly on Vercel

**Once you complete these steps, paste "Firebase setup complete" and I'll finish the migration!**
