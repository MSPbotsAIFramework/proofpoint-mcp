# Copyright 2026 MSPbots.ai
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Process settings. Holds no credentials: those arrive per request as headers."""

from pydantic_settings import BaseSettings, SettingsConfigDict

# TAP APIs (SIEM, Campaign, Forensics, People, Threat, URL Decoder): HTTP Basic
# with the TAP service principal and secret.
DEFAULT_TAP_URL = "https://tap-api-v2.proofpoint.com"
# Dashboard Reports APIs: Bearer token from a separate API key and secret
# (Admin Portal > Settings > API Key Management > Threat Protection).
REPORTS_API = "https://threatprotection-api.proofpoint.com/api/v1/dash/reports"
REPORTS_TOKEN_URL = "https://auth.proofpoint.com/v1/token"
# A caller-supplied base URL must stay on Proofpoint's own domain.
ALLOWED_HOST_SUFFIX = ".proofpoint.com"


class Settings(BaseSettings):
    # extra="ignore": the runtime injects variables this project does not declare.
    model_config = SettingsConfigDict(extra="ignore")

    mcp_http_port: int = 8080
    mcp_http_host: str = "0.0.0.0"
    log_level: str = "INFO"


def get_settings() -> Settings:
    return Settings()
