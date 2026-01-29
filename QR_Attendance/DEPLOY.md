# Deployment Guide - QR Attendance System (Render - FREE)

## Quick Deploy to Render

### Step 1: Push to GitHub
```bash
git add .
git commit -m "Add Render deployment configuration"
git push origin main
```

### Step 2: Deploy on Render
1. Go to [render.com](https://render.com) → Sign up with GitHub
2. Click **"New +"** → **"Web Service"**
3. Connect your GitHub repo
4. Configure:
   - **Name:** qr-attendance
   - **Runtime:** Go
   - **Build Command:** `go build -o main .`
   - **Start Command:** `./main`
5. Click **"Create Web Service"**

### Step 3: Set Environment Variable
In Render Dashboard → Your Service → **Environment**:

```
FIREBASE_CONFIG = <your firebase-credentials.json as single line>
```

**To minify your Firebase JSON (PowerShell):**
```powershell
(Get-Content firebase-credentials.json -Raw) -replace '\s+', ' '
```

### Step 4: Add Custom Domain (Namecheap)

**In Render:**
1. Go to your service → **Settings** → **Custom Domains**
2. Click **"Add Custom Domain"** → Enter your domain
3. Render shows DNS records to add

**In Namecheap:**
1. Domain List → Manage → **Advanced DNS**
2. Add the records Render provides (usually a CNAME)

---

## Free Tier Limits

| Resource | Free Tier |
|----------|-----------|
| Hours | 750/month (enough for 24/7) |
| Bandwidth | 100 GB/month |
| Build Minutes | 500/month |

⚠️ **Note:** Free tier apps spin down after 15 mins of inactivity. First request after sleep takes ~30 seconds.

---

## Your URLs

- **Render URL:** `https://qr-attendance.onrender.com`
- **Custom Domain:** `https://yourdomain.com`
- **Teacher QR:** `https://yourdomain.com/teacher-attendance`
