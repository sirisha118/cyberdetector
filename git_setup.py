"""Initialize git repo, add files, and create the first commit."""
import subprocess
import os

BASE = os.path.dirname(os.path.abspath(__file__))

# Ensure git is in PATH (just installed)
import shutil
git = shutil.which("git") or r"C:\Program Files\Git\cmd\git.exe"

def run(cmd):
    print(f"\n>>> {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=BASE)
    print(result.stdout)
    if result.stderr:
        print(result.stderr)
    return result.returncode

# 1. Initialize git repo
run([git, "init"])

# 2. Configure git user (change these to your real name/email)
run([git, "config", "user.name", "varikuppalashireesha"])
run([git, "config", "user.email", "varikuppalashireesha@users.noreply.github.com"])

# 3. Add all files (respects .gitignore)
run([git, "add", "-A"])

# 4. Show what will be committed
run([git, "status"])

# 5. Create the first commit
run([git, "commit", "-m", "CyberShield: AI-Powered Email Threat Detection System - Flask web app with email/SMS scam detection, URL reputation, ML classifier, IMAP/Gmail OAuth, REST API, responsive dashboard"])

# 6. Show final status
run([git, "log", "--oneline", "-1"])
run([git, "status"])

print("\n" + "="*60)
print("GIT REPO READY! Next steps:")
print("="*60)
print("""
1. Go to https://github.com/new
2. Repository name: cybershield
3. Set to PUBLIC or PRIVATE (your choice)
4. Do NOT check 'Add a README' or '.gitignore' (already have them)
5. Click 'Create repository'
6. Copy the URL (looks like: https://github.com/YOUR_USERNAME/cybershield.git)
7. Run these commands in terminal:

   git remote add origin https://github.com/YOUR_USERNAME/cybershield.git
   git branch -M main
   git push -u origin main

   (It will ask for GitHub login - use browser or personal access token)
""")
