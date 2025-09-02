# Version Control

Effective version control practices enable team collaboration, maintain code history, and provide safety nets for development. These guidelines focus on Git best practices.

## 🎯 Core Principles

1. **Atomic Commits** - Each commit should represent a single logical change
2. **Clear History** - Commit messages should tell the story of your changes
3. **Collaboration Ready** - Use branches and reviews to enable team development
4. **Safety First** - Always have a way to revert or recover changes

## 📝 Commit Message Guidelines

### Format Structure

Use the conventional commit format for consistency:

```example
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

### Commit Types

**✅ Good Examples:**

```bash
# Feature commits
feat(auth): add password reset functionality
feat(api): implement user search endpoint
feat: add dark mode support

# Bug fixes
fix(payment): prevent double charge on retry
fix(ui): correct button alignment in mobile view
fix: resolve memory leak in image processing

# Documentation
docs(api): update authentication examples
docs: add deployment instructions to README

# Refactoring
refactor(user-service): extract validation logic
refactor: simplify error handling middleware

# Performance improvements
perf(database): optimize user query with indexing
perf: reduce bundle size by lazy loading components

# Tests
test(auth): add integration tests for login flow
test: increase coverage for payment processing

# Build/tooling
build: update dependencies to latest versions
ci: add automated security scanning
chore: configure ESLint rules
```

### ❌ Avoid: Vague or unhelpful messages

```bash
# Too vague
git commit -m "fix stuff"
git commit -m "update code"
git commit -m "changes"

# Too technical without context
git commit -m "refactor UserService.validateInput method"
git commit -m "add null check in line 42"

# Multiple unrelated changes
git commit -m "fix login bug and update documentation and add new feature"
```

### Detailed Commit Messages

For complex changes, provide additional context:

**✅ Good Example:**

```example
feat(auth): implement OAuth2 integration

Add support for Google and GitHub OAuth2 providers to improve
user onboarding experience. Users can now sign up and login
using their existing accounts.

Changes include:
- OAuth2 strategy implementation for Passport.js
- New user registration flow for OAuth users
- Account linking for existing users
- Updated UI with OAuth login buttons

Resolves: #123, #145
Breaking change: Requires new environment variables for OAuth client credentials

Co-authored-by: Jane Doe <jane@example.com>
```

### Commit Message Best Practices

```bash
# ✅ Use imperative mood (like Git itself)
"Add user authentication"
"Fix memory leak in image processor"
"Remove deprecated API endpoints"

# ❌ Avoid past tense or present continuous
"Added user authentication"
"Fixing memory leak"
"Removes deprecated API"

# ✅ Be specific about what changed
"Fix validation error for email format"
"Add caching to user profile endpoint"

# ❌ Avoid generic descriptions
"Fix bug"
"Update file"
"Add feature"

# ✅ Reference issues when relevant
"fix(auth): resolve session timeout issue (#456)"
"feat: add export functionality (closes #123)"

# ✅ Use breaking change notation when needed
"feat!: remove support for Node.js 14"
"BREAKING CHANGE: API now requires authentication"
```

## 🌿 Branching Strategy

### Git Flow Pattern

```example
main (production-ready code)
├── develop (integration branch)
    ├── feature/user-authentication
    ├── feature/payment-processing
    ├── feature/admin-dashboard
    ├── hotfix/critical-security-patch
    └── release/v2.1.0
```

### Branch Naming Conventions

**✅ Good Branch Names:**

```bash
# Features
feature/user-authentication
feature/payment-integration
feature/admin-dashboard

# Bug fixes
fix/login-redirect-issue
fix/payment-validation-error
bugfix/memory-leak-in-processor

# Hotfixes
hotfix/critical-security-patch
hotfix/payment-gateway-outage

# Releases
release/v2.1.0
release/v2.1.1

# Experiments
experiment/new-ui-framework
spike/performance-optimization
```

### ❌ Avoid: Unclear or personal branch names

```bash
# Too vague
my-changes
updates
temp-branch

# Personal identifiers
johns-work
team-a-branch

# Inconsistent naming
Feature-New-Login
fix_bug_123
UPDATE-documentation
```

### Branch Workflow

**✅ Good Workflow:**

```bash
# 1. Start from updated main branch
git checkout main
git pull origin main

# 2. Create feature branch
git checkout -b feature/user-profile-page

# 3. Make commits with clear messages
git add src/components/UserProfile.js
git commit -m "feat(ui): add user profile component"

git add src/api/userApi.js
git commit -m "feat(api): add user profile endpoint"

git add tests/userProfile.test.js
git commit -m "test(ui): add user profile component tests"

# 4. Push branch and create pull request
git push origin feature/user-profile-page
# Create PR through GitHub/GitLab interface

# 5. After review and approval, merge to main
# Use "Squash and merge" for cleaner history if needed
```

## 🔍 Code Review Practices

### Creating Pull Requests

**✅ Good PR Template:**

```markdown
## Summary
Brief description of what this PR accomplishes.

## Changes Made
- Add user authentication system
- Implement password hashing with bcrypt
- Add login/logout endpoints
- Create user session management

## Testing
- [x] Unit tests pass
- [x] Integration tests added
- [x] Manual testing completed
- [ ] Performance testing (if applicable)

## Screenshots/Demo
(Include screenshots for UI changes)

## Related Issues
Closes #123
Relates to #456

## Checklist
- [x] Code follows project style guidelines
- [x] Self-review completed
- [x] Documentation updated
- [x] No breaking changes (or breaking changes documented)
```

### Review Guidelines

**✅ Good Review Comments:**

```markdown
# Constructive feedback
"Consider extracting this validation logic into a separate function 
for better reusability and testing."

# Ask clarifying questions
"What happens if the API returns a 500 error here? Should we add 
error handling?"

# Suggest improvements
"This looks good! We could improve performance by adding memoization 
to this calculation."

# Praise good work
"Great use of error boundaries here! This will make debugging much easier."

# Reference standards
"Per our coding standards, could we add JSDoc comments to this 
public method?"
```

### ❌ Avoid: Unhelpful or harsh comments

```markdown
# Too vague
"This is wrong."
"Fix this."

# Personal attacks
"You always write code like this."
"This is terrible."

# Nitpicking without value
"Extra space here."
"Missing comma."

# Commands without explanation
"Change this to use async/await."
"Don't use var."
```

## 🔄 Merging Strategies

### When to Use Different Merge Types

**Merge Commit** - Preserves complete history:

```bash
git checkout main
git merge feature/user-auth --no-ff
```

Use when: Feature branch has valuable commit history

**Squash and Merge** - Creates clean linear history:

```bash
git checkout main
git merge feature/user-auth --squash
git commit -m "feat(auth): implement user authentication system"
```

Use when: Feature branch has messy commit history

**Rebase and Merge** - Linear history without merge commits:

```bash
git checkout feature/user-auth
git rebase main
git checkout main
git merge feature/user-auth --ff-only
```

Use when: Want linear history and feature branch is up-to-date

## 🏷️ Tagging and Releases

### Semantic Versioning

```bash
# Major version: Breaking changes
git tag -a v2.0.0 -m "Release v2.0.0: Major API redesign"

# Minor version: New features, backward compatible
git tag -a v1.5.0 -m "Release v1.5.0: Add user preferences"

# Patch version: Bug fixes
git tag -a v1.4.1 -m "Release v1.4.1: Fix login redirect issue"

# Pre-release versions
git tag -a v2.0.0-beta.1 -m "Release v2.0.0-beta.1: Beta release"
git tag -a v2.0.0-rc.1 -m "Release v2.0.0-rc.1: Release candidate"
```

### Release Notes

**✅ Good Release Notes:**

```markdown
# v2.1.0 - 2024-01-15

## 🚀 New Features
- **User Profiles**: Users can now customize their profiles with avatars and bio
- **Dark Mode**: Added system-wide dark mode support
- **Export Data**: Users can export their data in JSON or CSV format

## 🐛 Bug Fixes
- Fixed login redirect issue after password reset
- Resolved memory leak in image processing
- Corrected timezone display in user dashboard

## 🔧 Improvements
- Improved page load times by 30%
- Enhanced accessibility with better keyboard navigation
- Updated dependency versions for security patches

## ⚠️ Breaking Changes
- API endpoint `/api/v1/users` now requires authentication
- Removed deprecated `getUserData()` method (use `getUser()` instead)

## 📦 Dependencies
- Updated React to v18.2.0
- Updated Express to v4.18.2
- Added @types/node v18.11.18

## 🔐 Security
- Fixed vulnerability in user input validation
- Enhanced password strength requirements
- Updated all dependencies to latest secure versions

## 🏗️ Internal Changes
- Refactored authentication middleware
- Improved test coverage to 95%
- Updated CI/CD pipeline for faster builds
```

## 🛠️ Git Configuration

### Useful Git Aliases

```bash
# Add to ~/.gitconfig
[alias]
    # Short status
    s = status -s
    
    # Pretty log
    lg = log --oneline --graph --decorate --all
    
    # Show last commit
    last = log -1 HEAD --stat
    
    # Undo last commit but keep changes
    undo = reset HEAD~1 --mixed
    
    # Clean up merged branches
    cleanup = "!git branch --merged | grep -v '\\*\\|main\\|develop' | xargs -n 1 git branch -d"
    
    # Show commits not yet pushed
    unpushed = log @{u}..
    
    # Show what was changed in last commit
    dl = diff --cached HEAD~1
    
    # Amend commit without editing message
    oops = commit --amend --no-edit
```

### Git Hooks

**Pre-commit Hook** (`.git/hooks/pre-commit`):

```bash
#!/bin/sh
# Run linting and tests before commit

echo "Running pre-commit checks..."

# Run linter
npm run lint
if [ $? -ne 0 ]; then
    echo "❌ Linting failed. Please fix errors before committing."
    exit 1
fi

# Run tests
npm test
if [ $? -ne 0 ]; then
    echo "❌ Tests failed. Please fix tests before committing."
    exit 1
fi

echo "✅ Pre-commit checks passed!"
```

## 🚫 Common Anti-Patterns

### Avoid These Git Practices

**❌ Committing Generated Files:**

```bash
# Don't commit these
git add dist/
git add node_modules/
git add .env
git add *.log
git add .DS_Store
```

**❌ Force Pushing to Shared Branches:**

```bash
# Never do this on main/shared branches
git push --force origin main
git push -f origin develop
```

**❌ Committing Work-in-Progress:**

```bash
# Avoid commits like these
git commit -m "WIP"
git commit -m "temp commit"
git commit -m "save work"
```

**❌ Large Binary Files:**

```bash
# Don't commit large files directly
git add videos/demo.mp4
git add datasets/large-data.csv
git add images/high-res-photos/
```

## ✅ Quick Checklist

- [ ] Commit messages follow conventional format
- [ ] Each commit represents a single logical change
- [ ] Branch names are descriptive and follow conventions
- [ ] Pull requests include clear descriptions and testing notes
- [ ] Code reviews are constructive and helpful
- [ ] No sensitive data (passwords, keys) committed
- [ ] `.gitignore` excludes generated files and dependencies
- [ ] Releases are tagged with semantic versioning
- [ ] Git hooks prevent bad commits
- [ ] Remote branches are cleaned up after merging

---

**Next:** [Security & Privacy](./security-privacy.md)
