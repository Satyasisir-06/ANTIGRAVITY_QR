# Go Setup & Run Guide

The error `The term 'go' is not recognized` means **Go is not installed** on your computer (or the terminal hasn't been restarted after installation).

## Step 1: Install Go
You **must** install Go to run this code locally. I cannot install it for you.

1.  **Download & Install:** [https://go.dev/dl/](https://go.dev/dl/)
2.  **Restart VS Code** (or terminal) after installation.
3.  **Verify:**
    ```powershell
    go version
    ```
*If it shows `go version go1.21...`, you are ready.*

## Step 3: Run the App
Navigate to the folder:
```powershell
cd "e:\antigravity QR\QR_Attendance"
```

Initialize dependencies (only needed once):
```powershell
go mod tidy
```

Start the server:
```powershell
go run main.go
```

## Step 4: Open in Browser
Go to: **http://localhost:8080**

---

## Deployment (Vercel)
When you are ready to deploy:
1.  Push this code to GitHub.
2.  Import the project in Vercel.
3.  Vercel will automatically detect `go.mod` and deploy it as a serverless Go app.
4.  **No 2GB Limit:** Since Go compiles to a tiny file, you will no longer face the storage limit error.
