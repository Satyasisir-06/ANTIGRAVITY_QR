# FIX: Connect Vercel to Supabase Database

## THE PROBLEM
Your Vercel deployment is using SQLite (local, empty database) instead of Supabase (cloud, has your data).

## THE SOLUTION
Add the DATABASE_URL environment variable to Vercel.

### Step 1: Get Your Supabase Connection String
1. Go to your Supabase project dashboard
2. Click **Settings** (gear icon) → **Database**
3. Scroll to **Connection String** section
4. Copy the **URI** (it should look like):
   ```
   postgresql://postgres:[YOUR-PASSWORD]@[HOST].supabase.co:5432/postgres
   ```
5. Replace `[YOUR-PASSWORD]` with your actual database password

### Step 2: Add to Vercel
1. Go to https://vercel.com/dashboard
2. Click on your **antigravity** project
3. Go to **Settings** tab
4. Click **Environment Variables** in the left sidebar
5. Add a new variable:
   - **Name:** `DATABASE_URL`
   - **Value:** (paste the connection string from Step 1)
   - **Environment:** Check all boxes (Production, Preview, Development)
6. Click **Save**

### Step 3: Redeploy
1. Go to **Deployments** tab
2. Click the **...** menu on the latest deployment
3. Click **Redeploy**
4. Wait for it to finish (~1 minute)

### Step 4: Test
After redeployment, try this link:
```
https://antigravity-9b8h8x3fo-newtechsisir-9095s-projects.vercel.app/debug/force_teacher_login/CEC25865
```

It should now find the user and redirect you to the dashboard!

---

## Quick Verification
If you want to verify the DATABASE_URL is working, check the Vercel logs after redeployment.
It should say "[STARTUP] Initializing Database..." and connect to Postgres, not SQLite.
