# Keeper Slack App

Slack integration for Keeper Security that enables secure credential access requests, approval workflows, and one-time share links directly within Slack. Zero knowledge end-to-end encryption is preserved through the use of a self-hosted application container.

## Overview

This app connects Slack with Keeper Commander Service Mode, allowing teams to:

- Request access to records and folders with approval workflows
- Generate one-time share links for external sharing
- Approve or deny PEDM (Privileged Elevation) requests
- Approve or deny Cloud SSO Device Approval requests
- Search records and folders by name or UID

The app uses Socket Mode, so no public endpoint is required.

## Security

The customer is responsible for hosting the Slack App and Commander Service Mode. Step by step setup instructions are available in the [KeeperPAM Slack App](https://docs.keeper.io/en/keeperpam/secrets-manager/integrations/slack-app) integration page.

### Security Features

- **Input Sanitization**: All user inputs are sanitized to prevent command injection and URL injection attacks
- **URL Injection Protection**: Colons and forward slashes are filtered from user inputs to prevent phishing links
- **Slack Mention Prevention**: `@here`, `@channel`, and `@everyone` mentions are automatically removed
- **PAM Record Protection**: PAM records are excluded from search results and cannot be shared via one-time links
- **KSM Integration**: Credentials are securely stored in Keeper Secrets Manager
- **Docker URL Auto-Fix**: Automatically converts `localhost` to `commander` when running in Docker containers

## Prerequisites

- Docker and Docker Compose
- Keeper Commander
- Slack workspace with admin access

---

## Quick Start (Recommended)

The easiest way to set up the Keeper Slack App is using the built-in setup command in Keeper Commander.

### Step 1: Create Your Slack App

Before running the setup command, create your Slack app:

1. Go to https://api.slack.com/apps and create a new app
2. Use the manifest in `slack_manifest.yaml` or configure manually:
   - Enable Socket Mode and generate an App-Level Token (`xapp-`)
   - Add bot scopes: `chat:write`, `commands`, `im:write`, `users:read`, `channels:read`
   - Create slash commands: `/keeper-request-record`, `/keeper-request-folder`, `/keeper-one-time-share`
   - Enable the App Home tab
   - Install the app to your workspace and copy the Bot Token (`xoxb-`)
3. Copy the Signing Secret from Basic Information
4. Create a channel for approval requests and note its Channel ID

### Step 2: Clone and Login to Commander

```bash
# Clone the Commander repository
git clone https://github.com/Keeper-Security/Commander.git
cd Commander

# Start Keeper shell and login
keeper shell
My Vault> login your@email.com
```

### Step 3: Run the Slack App Setup Command

```bash
My Vault> slack-app-setup
```

This interactive command will guide you through the complete setup:

**Phase 1: Docker Service Mode Setup**
```
═══════════════════════════════════════════════════════════
    Docker Setup
═══════════════════════════════════════════════════════════

[1/7] Checking device settings...
  ✓  Device already registered
  ✓  Persistent login already enabled

[2/7] Creating shared folder 'Commander Service Mode - Slack App'...
  ✓  Using existing shared folder

[3/7] Creating record 'Commander Service Mode Docker Config'...
  ✓  Using existing record

[4/7] Uploading config.json attachment...
  ✓  Config file uploaded successfully

[5/7] Creating Secrets Manager app 'Commander Service Mode - KSM App'...
  ✓  Using existing app

[6/7] Sharing folder with app...
  ✓  Folder shared with app

[7/7] Creating client device and generating config...
  ✓  Client device created successfully

✓ Docker Setup Complete!
```

**Service Mode Configuration**
```
═══════════════════════════════════════════════════════════
    Service Mode Configuration
═══════════════════════════════════════════════════════════

Port [Press Enter for 8900]: 8900
Enable ngrok? [Press Enter for No] (y/n): n
Enable Cloudflare? [Press Enter for No] (y/n): n

✓ Service Mode Configuration Complete!
```

**Phase 2: Slack App Configuration**
```
═══════════════════════════════════════════════════════════
    Slack App Configuration
═══════════════════════════════════════════════════════════

SLACK_APP_TOKEN:
  App-level token for Slack App
Token (starts with xapp-): xapp-1-xxxxx-xxxxx-xxxxx

SLACK_BOT_TOKEN:
  Bot token for Slack workspace
Token (starts with xoxb-): xoxb-xxxxx-xxxxx-xxxxx

SLACK_SIGNING_SECRET:
  Signing secret for verifying Slack requests
Secret: xxxxx

APPROVALS_CHANNEL_ID:
  Slack channel ID for approval notifications
Channel ID (starts with C): C0XXXXXXX

Enable PEDM? [Press Enter for No] (y/n): n
Enable Device Approval? [Press Enter for No] (y/n): n

✓ Slack Configuration Complete!
```

### Step 4: Start the Services

```bash
docker compose up -d
```

That's it! Your Keeper Slack App is now running.

### View Logs

```bash
docker compose logs -f
```

---

## Docker Commands Reference

| Action | Command |
|--------|---------|
| Start | `docker compose up -d` |
| Stop | `docker compose down` |
| Restart | `docker compose restart` |
| View logs | `docker compose logs -f` |
| Rebuild | `docker compose build --no-cache` |
| Check status | `docker compose ps` |

### Docker Notes

- Logs are persisted to `./logs/` directory
- Container auto-restarts unless explicitly stopped
- If using ngrok, the app includes the required `ngrok-skip-browser-warning` header

---

## Local Development (For Testing Only)

For development and testing without Docker:

### Step 1: Set up Python environment

```bash
# Create virtual environment
python3 -m venv keeper-env

# Activate it
source keeper-env/bin/activate  # macOS/Linux
# or
keeper-env\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
```

### Step 2: Create configuration file

```bash
cp slack_config.example.yaml slack_config.yaml
```

Edit `slack_config.yaml`:

```yaml
slack:
  app_token: "xapp-1-xxxxx"
  bot_token: "xoxb-xxxxx"
  signing_secret: "xxxxx"
  approvals_channel_id: "C0XXXXXXX"

keeper:
  service_url: "http://localhost:8900/api/v2/"
  api_key: "your-keeper-api-key"

pedm:
  enabled: false
  polling_interval: 120

device_approval:
  enabled: false
  polling_interval: 120
```

### Step 3: Start Keeper Commander Service Mode

```bash
keeper shell --service-mode --port 8900
```

### Step 4: Run the app

```bash
python run_slack.py
```

---

## Commands

### /keeper-request-record

Request access to a Keeper record.

```
/keeper-request-record <record-uid-or-description> <justification>
```

Example:
```
/keeper-request-record kR3cF9Xm2Lp8NqT1uV6w Need access for deployment
```

### /keeper-request-folder

Request access to a Keeper folder.

```
/keeper-request-folder <folder-uid-or-description> <justification>
```

Example:
```
/keeper-request-folder "Engineering Creds" Project onboarding
```

### /keeper-one-time-share

Request a one-time share link for a record.

```
/keeper-one-time-share <record-uid-or-description> <justification>
```

Example:
```
/keeper-one-time-share kR3cF9Xm2Lp8NqT1uV6w Share with contractor
```

---

## Approval Workflow

1. User runs a slash command with UID/description and justification
2. Request is posted to the approvals channel
3. Approver selects permission level and duration
4. Approver clicks Approve or Deny
5. User receives a DM with the result (access granted or denied)

### Permission Levels

**Record permissions:**
- View Only (time-limited)
- Can Edit (time-limited)
- Can Share (permanent only)
- Edit and Share (permanent only)
- Change Owner (permanent only)

**Folder permissions:**
- No Permissions (time-limited)
- Manage Users (permanent only)
- Manage Records (time-limited)
- Manage All (permanent only)

### Duration Options

- 1 hour
- 4 hours
- 8 hours
- 24 hours
- 7 days
- 30 days
- Permanent

---

## PEDM (Keeper Endpoint Privilege Manager)

To enable PEDM polling during setup, answer `y` when prompted:

```
Enable PEDM? [Press Enter for No] (y/n): y
```

For local development, configure in `slack_config.yaml`:

```yaml
pedm:
  enabled: true
  polling_interval: 120
```

The app will poll for pending PEDM requests and post them to the approvals channel.

### PEDM Request Handling

- Requests that have already been processed elsewhere show "Already processed (approved/denied elsewhere)"
- Approvers see clear status updates after each action

---

## Cloud SSO Device Approval

To enable Cloud SSO Device Approval during setup, answer `y` when prompted:

```
Enable Device Approval? [Press Enter for No] (y/n): y
```

For local development, configure in `slack_config.yaml`:

```yaml
device_approval:
  enabled: true
  polling_interval: 120
```

The app will poll for pending device approval requests and post them to the approvals channel.

---

## Troubleshooting

### Cannot reach Keeper Service Mode

Ensure Keeper Commander is running:
```bash
keeper shell --service-mode --port 8900
```

**For Docker:** The app automatically converts `localhost` to `commander` in service URLs. If using a different container name, update your KSM record or config accordingly.

**For host services:** Use `host.docker.internal` to reach services running on your host machine.

### Channel not found

- Verify the channel ID in config is correct
- Invite the bot to the channel: `/invite @Keeper Security`

### Socket Mode connection failed

- Check that the app_token starts with `xapp-`
- Verify Socket Mode is enabled in Slack app settings

### PAM Records Not Showing in Search

PAM records (pamDirectory, pamDatabase, pamMachine, pamUser, pamRemoteBrowser) are intentionally excluded from search results for security reasons.

### One-Time Share Fails for PAM Records

One-time share links cannot be created for PAM records. Users will see a clear error message explaining this limitation.

### Duplicate Slash Commands

If you see duplicate slash commands in Slack:
1. Check if multiple apps with the same name are installed in your workspace
2. Go to Slack Settings > Manage Apps and remove any duplicate installations
3. Ensure only one app is registered with the slash commands

---

## KSM (Keeper Secrets Manager) Integration

The `slack-app-setup` command automatically configures KSM for secure credential storage. All credentials are stored securely in your Keeper Vault and accessed via KSM - no plaintext configuration files are needed.

### What Gets Stored in KSM

The setup command creates records containing:

**Service Mode Configuration:**
- `service_url` - Service Mode API URL
- `api_key` - Service Mode API key

**Slack Configuration:**
- `slack_app_token` - Slack App Token (xapp-)
- `slack_bot_token` - Slack Bot Token (xoxb-)
- `slack_signing_secret` - Slack Signing Secret
- `approvals_channel_id` - Channel ID for approval requests
- `pedm_enabled` - Enable PEDM polling (true/false)
- `pedm_polling_interval` - PEDM polling interval in seconds
- `device_approval_enabled` - Enable device approval polling (true/false)
- `device_approval_polling_interval` - Device approval polling interval in seconds

---

## Changelog

### Recent Updates

- **Automated Setup Command**: New `slack-app-setup` command for one-step configuration
- **PAM Record One-Time Share Protection**: One-time share blocked for PAM records with user-friendly error
- **URL Injection Protection**: Colons and forward slashes sanitized to prevent phishing links
- **PEDM Already Processed Handling**: Clear status when PEDM requests were processed elsewhere
- **Cloud SSO Device Approval**: Support for device approval polling and actions
- **KSM Integration**: Secure credential storage via Keeper Secrets Manager
- **Consistent Input Sanitization**: Slack markdown characters cleaned from all identifiers
- **Simplified Logging**: Cleaner credential fetch logs

---

## License

Copyright 2025 Keeper Security Inc.
Contact: commander@keepersecurity.com
