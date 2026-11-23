# CI/CD Pipeline Guide for IP Lookup Project

This guide explains the GitHub Actions CI/CD pipeline configured for the IP Lookup project.

## Overview

The CI/CD pipeline automatically runs on every push and pull request to the `main` and `develop` branches. It performs the following checks and operations:

```
Lint → Test → Security → Build → Deploy
```

## Pipeline Jobs

### 1. **Lint & Format Check** (`lint` job)
Runs code quality checks to ensure consistent code style and identify potential issues.

**Tools Used:**
- **Black**: Python code formatter - ensures consistent formatting
- **isort**: Import sorter - organizes imports consistently
- **Flake8**: Linter - catches common Python errors and style violations
- **Pylint**: Advanced linter - provides comprehensive code quality analysis

**Configuration Files:**
- `.flake8` - Flake8 configuration
- `.pylintrc` - Pylint configuration
- `pyproject.toml` - Black and isort settings

**What it checks:**
- Code formatting compliance
- Import organization
- PEP 8 style violations
- Undefined variables, unused imports
- Complexity metrics

### 2. **Run Tests** (`test` job)
Executes unit tests and generates coverage reports.

**Tools Used:**
- **pytest**: Test runner
- **pytest-cov**: Coverage reporting
- **pytest-mock**: Mocking library
- **Codecov**: Coverage tracking (optional integration)

**What it does:**
- Runs all tests in the `tests/` directory
- Generates code coverage reports
- Uploads results to Codecov (optional)
- Continues even if tests fail to show results

**Test File:** `tests/test_ip_lookup.py`

**Running Tests Locally:**
```bash
# Install test dependencies
pip install pytest pytest-cov pytest-mock

# Run all tests
pytest tests/ -v

# Run with coverage report
pytest tests/ -v --cov=. --cov-report=html
```

### 3. **Security Scan** (`security` job)
Performs security vulnerability checks.

**Tools Used:**
- **Bandit**: Scans for common security issues in Python
- **Safety**: Checks dependencies for known vulnerabilities

**Configuration:**
- Bandit generates a JSON report (bandit-report.json)
- Safety checks the requirements against known CVEs

**What it checks:**
- Hardcoded secrets or credentials
- SQL injection vulnerabilities
- Insecure random number generation
- Known vulnerable dependencies

### 4. **Build Application** (`build` job)
Builds and packages the application for deployment.

**What it does:**
- Verifies Python 3.11 compatibility
- Installs all dependencies
- Verifies the application can be imported
- Creates a dist/ artifact with necessary files

**Artifacts Created:**
- `dist/ip-lookup.py` - Main application
- `dist/requirements.txt` - Dependencies
- `dist/README.md` - Documentation

### 5. **Deploy** (`deploy` job)
Handles deployment of the application (triggered only on main branch pushes).

**Conditions:**
- Only runs on `main` branch pushes (not on PRs)
- Only runs after all other jobs succeed

**What it does:**
- Sets up Python environment
- Installs dependencies
- Creates release notes
- Outputs deployment success message

**Customization:**
You can extend this job to:
- Deploy to a cloud service (AWS, Azure, GCP, Heroku)
- Push to Docker Hub
- Create GitHub releases
- Send notifications to Slack/Discord

## Configuration Files

### `.github/workflows/ci-cd.yml`
Main workflow configuration - defines all jobs, steps, and triggers.

### `pyproject.toml`
Centralized configuration for Black, isort, and pytest.

### `.flake8`
Configuration for Flake8 linting rules.

### `.pylintrc`
Configuration for Pylint analysis settings.

### `requirements.txt`
Updated with development dependencies needed for CI/CD.

## Setting Up CI/CD

### Prerequisites
1. GitHub repository with this code
2. Branches configured: `main` and `develop`
3. No special secrets needed initially (AbuseIPDB key only needed for actual runs)

### Steps to Enable

1. **Push the workflow file**
   ```bash
   git add .github/workflows/ci-cd.yml
   git commit -m "Add CI/CD pipeline"
   git push
   ```

2. **Go to your GitHub repository**
   - Navigate to Actions tab
   - You should see "CI/CD Pipeline" listed

3. **Configure Secrets (Optional)**
   For the pipeline to run your actual application:
   - Go to Repository Settings → Secrets and variables → Actions
   - Add `ABUSEIPDB_API_KEY` if you want tests to use real API data
   
   ```bash
   # Command line (using GitHub CLI)
   gh secret set ABUSEIPDB_API_KEY --body "your-api-key"
   ```

## Running Locally (Before Pushing)

You can simulate the pipeline locally:

```bash
# 1. Install development dependencies
pip install -r requirements.txt

# 2. Run linting
black --check .
isort --check-only .
flake8 .
pylint ip-lookup.py

# 3. Run tests
pytest tests/ -v --cov=.

# 4. Run security checks
bandit -r .
safety check
```

Or use a tool like **act** to run the full workflow locally:

```bash
# Install act: https://github.com/nektos/act
act push

# Act will run the entire workflow on your machine
```

## Branch Protection Rules (Recommended)

To enforce CI/CD checks before merging:

1. Go to Repository Settings → Branches
2. Add rule for `main` branch:
   - Require status checks to pass before merging
   - Select: `lint`, `test`, `security`, `build`
   - Dismiss stale pull request approvals when new commits are pushed
3. Add rule for `develop` branch (optional):
   - Same as above, or less strict depending on your workflow

## Workflow Status Badges

Add this to your README.md to show CI/CD status:

```markdown
[![CI/CD Pipeline](https://github.com/YOUR-USERNAME/ip-lookup/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/YOUR-USERNAME/ip-lookup/actions)
```

Replace `YOUR-USERNAME` with your GitHub username.

## Troubleshooting

### Pipeline Fails on "Run Tests"
- Ensure `tests/test_ip_lookup.py` exists
- Check that test file imports work correctly
- Use `pytest --collect-only` to debug test discovery

### Pipeline Fails on "Run Flake8"
- Fix errors: `black .` and `isort .`
- Ignore specific errors if needed in `.flake8`

### Pipeline Fails on "Security Scan"
- Review Bandit findings: check `bandit-report.json`
- Update dependencies if security vulnerabilities found
- Some warnings are low-risk and can be suppressed

### Deployment Doesn't Trigger
- Ensure you're pushing to `main` branch (not `develop`)
- Check that all previous jobs passed
- Review job conditions in `.github/workflows/ci-cd.yml`

## Advanced Customization

### Add Docker Build & Push
```yaml
- name: Build and push Docker image
  uses: docker/build-push-action@v4
  with:
    push: true
    tags: username/ip-lookup:latest
```

### Add Cloud Deployment
```yaml
- name: Deploy to Heroku
  uses: AkhileshNS/heroku-deploy@v3.12.12
  with:
    heroku_api_key: ${{ secrets.HEROKU_API_KEY }}
    heroku_app_name: "your-app-name"
```

### Add GitHub Release
```yaml
- name: Create Release
  uses: actions/create-release@v1
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    tag_name: v${{ github.run_number }}
    release_name: Release v${{ github.run_number }}
```

### Add Slack Notifications
```yaml
- name: Notify Slack
  uses: 8398a7/action-slack@v3
  if: always()
  with:
    status: ${{ job.status }}
    webhook_url: ${{ secrets.SLACK_WEBHOOK }}
```

## Resources

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [pytest Documentation](https://docs.pytest.org/)
- [Black Code Formatter](https://github.com/psf/black)
- [Flake8 Documentation](https://flake8.pycqa.org/)
- [Pylint Documentation](https://pylint.pycqa.org/)
- [Bandit Security Linter](https://bandit.readthedocs.io/)

## Support

For issues or questions:
1. Check GitHub Actions logs: Repository → Actions → Workflow run
2. Review the error messages in the failed job
3. Consult the tool documentation links above
4. Test locally using `act` before pushing
