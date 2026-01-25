from app import app

# Vercel looks for 'app' in this file
# This is a standard pattern for Vercel Python deployments
if __name__ == '__main__':
    app.run()
