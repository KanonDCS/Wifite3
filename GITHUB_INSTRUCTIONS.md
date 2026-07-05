# Wifite 3 — GitHub Upload Instructions

Follow these step-by-step instructions to initialize your local git repository and push it to your GitHub account under `KanonDCS/Wifite3`.

---

## 1. Configure Git (If not done already)
Set your name and email address:
```bash
git config --global user.name "KanonDCS"
git config --global user.email "kanondcs@proton.me"
```

---

## 2. Initialize Git Repository
Navigate to the project folder, initialize a new Git repository, and stage all files:
```bash
cd /home/ransom/Desktop/Wifite3
git init
git add .
```

---

## 3. Create the Initial Commit
Commit the staged files to your local repository:
```bash
git commit -m "Initialize Wifite 3: High-Performance Wireless Network Auditor"
```

---

## 4. Rename the Default Branch
Ensure the default branch is named `main`:
```bash
git branch -M main
```

---

## 5. Add the Remote Repository
Link your local repository to your GitHub repository:
```bash
git remote add origin https://github.com/KanonDCS/Wifite3.git
```

---

## 6. Push to GitHub
Push your local commit to your GitHub remote repository:
```bash
git push -u origin main
```
*(You will be prompted to enter your GitHub username and Personal Access Token (PAT) / password).*
