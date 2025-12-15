# Keeper Slack App

Slack integration for Keeper Security that enables secure credential access requests, approval workflows, and one-time share links directly within Slack. Zero knowledge end-to-end encryption is preserved through the use of a self-hosted application container.

## Overview

This app connects Slack with Keeper Commander Service Mode, allowing teams to:

- Request access to records and folders with approval workflows
- Generate one-time share links for external sharing
- Approve or deny PEDM (Privileged Elevation) requests
- Search records and folders by name or UID

The app uses Socket Mode, so no public endpoint is required.

## Security

The customer is responsible for hosting the Slack App and Commander Service Mode. Step by step setup instructions are available in the [KeeperPAM Slack App](https://docs.keeper.io/en/keeperpam/secrets-manager/integrations/slack-app) integration page.

## Prerequisites

- Python 3.9+
- Docker and Docker Compose (for Docker deployment)
- Keeper Commander running in Service Mode
- Slack workspace with admin access

## Slack App Setup

1. Go to https://api.slack.com/apps and create a new app
2. Use the manifest in `slack_manifest.yaml` or configure manually:
   - Enable Socket Mode and generate an App-Level Token (xapp-)
   - Add bot scopes: `chat:write`, `commands`, `im:write`, `users:read`, `channels:read`
   - Create slash commands: `/keeper-request-record`, `/keeper-request-folder`, `/keeper-one-time-share`
   - Enable the App Home tab
   - Install the app to your workspace and copy the Bot Token (xoxb-)
3. Copy the Signing Secret from Basic Information
4. Create a channel for approval requests and note its Channel ID

---

## Deployment Options

Choose one of the following deployment methods:

| Method | Config File | Best For |
|--------|-------------|----------|
| Docker | `.env` | Production deployment |
| Local | `slack_config.yaml` | Development and testing |

---

## Option 1: Docker Deployment (Recommended for Production)

### Step 1: Create the `.env` file

Copy the example and fill in your values:

```bash
cp env.example .env
```

Edit `.env` with your credentials:

```bash
# Slack Configuration
SLACK_APP_TOKEN=xapp-1-xxxxx-xxxxx-xxxxx
SLACK_BOT_TOKEN=xoxb-xxxxx-xxxxx-xxxxx
SLACK_SIGNING_SECRET=xxxxx
APPROVALS_CHANNEL_ID=C0XXXXXXX

# Keeper Configuration
# Use host.docker.internal to reach services on your host machine
KEEPER_SERVICE_URL=http://host.docker.internal:3001/api/v2/
KEEPER_API_KEY=your-keeper-api-key

# PEDM Configuration (Optional)
PEDM_ENABLED=false
PEDM_POLLING_INTERVAL=120
```

### Step 2: Start Keeper Commander Service Mode

On your host machine, start Keeper Commander:

```bash
keeper shell --service-mode --port 3001
```

### Step 3: Build and Run with Docker

```bash
# Build the Docker image
docker-compose build

# Start the container (detached mode)
docker-compose up -d

# View logs
docker-compose logs -f
```

### Docker Commands Reference

| Action | Command |
|--------|---------|
| Start | `docker-compose up -d` |
| Stop | `docker-compose down` |
| Restart | `docker-compose restart` |
| View logs | `docker-compose logs -f` |
| Rebuild | `docker-compose build --no-cache` |
| Check status | `docker-compose ps` |

### Docker Notes

- Logs are persisted to `./logs/` directory
- Container auto-restarts unless explicitly stopped
- Use `host.docker.internal` instead of `localhost` to reach host services
- If using ngrok, the app includes the required `ngrok-skip-browser-warning` header

---

## Option 2: Local Development

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

Copy the example and fill in your values:

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
  service_url: "http://localhost:3001/api/v2/"
  api_key: "your-keeper-api-key"

pedm:
  enabled: false
  polling_interval: 120
```

### Step 3: Start Keeper Commander Service Mode

```bash
keeper shell --service-mode --port 3001
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

To enable PEDM polling, set in your config:

**For Docker (`.env`):**
```
PEDM_ENABLED=true
PEDM_POLLING_INTERVAL=120
```

**For Local (`slack_config.yaml`):**
```yaml
pedm:
  enabled: true
  polling_interval: 120
```

The app will poll for pending PEDM requests and post them to the approvals channel.

---

## Troubleshooting

### Cannot reach Keeper Service Mode

Ensure Keeper Commander is running:
```bash
keeper shell --service-mode --port 3001
```

**For Docker:** Use `host.docker.internal` instead of `localhost` in your config.

### Channel not found

- Verify the channel ID in config is correct
- Invite the bot to the channel: `/invite @Keeper Security`

### Socket Mode connection failed

- Check that the app_token starts with `xapp-`
- Verify Socket Mode is enabled in Slack app settings

---

## License

Copyright 2025 Keeper Security Inc.
Contact: commander@keepersecurity.com
