# Prisma Cloud Health Check Script

This script interacts with the Prisma Cloud Console API to check agentless vulnerability scan coverage for onboarded cloud accounts. It provides a summary of scan results for selected accounts.

## Features
- Authenticates with Prisma Cloud using API Key/Secret
- Lists all onboarded cloud accounts for selection
- Queries scan results and agentless scan progress
- Summarizes scan coverage and status
- Logs errors to a log file

## Installation

1. Clone or download this repository to your local machine.
2. Install Python 3.7+ if not already installed.
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Copy `config.ini` and fill in your Prisma Cloud credentials and API URLs.

## Usage

1. Edit `config.ini` with your Prisma Cloud API Key, Secret, and relevant URLs.
2. Run the script:
   ```
   python prisma_cloud_health_check.py
   ```
3. Follow the prompts to select cloud accounts and view scan summaries.

## Logging

All errors and important events are logged to `prisma_cloud_health_check.log` in the script directory.

## Security
- Do **not** commit your API credentials to source control.
- The script stores the session token ephemerally in memory only.

## Support
For issues or questions, please contact your Prisma Cloud administrator or refer to the [Prisma Cloud API Docs](https://pan.dev/prisma-cloud/api/).
