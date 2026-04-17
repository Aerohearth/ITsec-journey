"""Configuration for the SOC Trainer app."""
import os
from dotenv import load_dotenv

load_dotenv()

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

# Data source URLs (all free, no auth required)
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CISA_ALERTS_RSS = "https://www.cisa.gov/uscert/ncas/alerts.xml"
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Model config
MODEL = "claude-opus-4-6"
MAX_TOKENS = 4096

# Display
APP_NAME = "SOC Analyst Trainer"
APP_VERSION = "1.0.0"
