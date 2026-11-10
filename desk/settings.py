from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str = Field(
        default="postgresql+asyncpg://desk:desk@localhost:5432/desk", alias="DATABASE_URL"
    )
    xe_node_url: str = Field(default="https://ldn.core.test.network", alias="XE_NODE_URL")
    public_base_url: str = Field(default="http://localhost:8010", alias="PUBLIC_BASE_URL")
    bounty_host: str = Field(default="", alias="DESK_BOUNTY_HOST")
    support_host: str = Field(default="", alias="DESK_SUPPORT_HOST")
    webauthn_rp_id: str = Field(default="", alias="WEBAUTHN_RP_ID")
    webauthn_rp_name: str = Field(default="XE Desk", alias="WEBAUTHN_RP_NAME")
    config_dir: Path = Field(default=Path("config"), alias="DESK_CONFIG_DIR")
    signer_keyfile: Path = Field(default=Path("secrets/signer.json"), alias="DESK_SIGNER_KEYFILE")
    signer_passphrase: str = Field(default="", alias="DESK_SIGNER_PASSPHRASE")
    blob_dir: Path = Field(default=Path("blobs"), alias="DESK_BLOB_DIR")
    github_token: str = Field(default="", alias="GITHUB_TOKEN")
    github_webhook_secret: str = Field(default="", alias="GITHUB_WEBHOOK_SECRET")
    github_bot_login: str = Field(default="", alias="GITHUB_BOT_LOGIN")  # the account GITHUB_TOKEN belongs to
    # GitHub accounts the desk does not take in (comma-separated; a login, or `id:<n>` for the number
    # GitHub gives the account, which a rename does not change): an issue one opens is not a ticket,
    # one it opened earlier takes no more from it, its pull requests are not linked and its comments
    # are not mirrored. For an account that farms patches against other people's reports and plants
    # payout addresses in the threads (XE-0128, XE-1876).
    github_blocked_logins: str = Field(default="", alias="GITHUB_BLOCKED_LOGINS")
    # Reporter sign-in with GitHub (an OAuth app; callback is {bounty host}/v1/reporter/auth/github/callback)
    github_oauth_client_id: str = Field(default="", alias="GITHUB_OAUTH_CLIENT_ID")
    github_oauth_client_secret: str = Field(default="", alias="GITHUB_OAUTH_CLIENT_SECRET")
    # Discord: the support bot (token, guild, the channel the panel lives in, the role that answers) and
    # reporter sign-in with Discord (the same application's OAuth2 client secret; client id = app id).
    discord_bot_token: str = Field(default="", alias="DISCORD_BOT_TOKEN")
    discord_app_id: str = Field(default="", alias="DISCORD_APP_ID")
    discord_oauth_client_secret: str = Field(default="", alias="DISCORD_OAUTH_CLIENT_SECRET")
    discord_guild_id: int = Field(default=0, alias="DISCORD_GUILD_ID")
    discord_support_channel_id: int = Field(default=0, alias="DISCORD_SUPPORT_CHANNEL_ID")
    discord_support_role_id: int = Field(default=0, alias="DISCORD_SUPPORT_ROLE_ID")
    # Filing limits
    max_attachment_mb: int = Field(default=10, alias="DESK_MAX_ATTACHMENT_MB")
    max_attachments: int = Field(default=5, alias="DESK_MAX_ATTACHMENTS")
    # Links for `internal_ref`. The tracker is xeprotocol/core (private; the link only resolves for the team).
    internal_tracker_url: str = Field(
        default="https://github.com/xeprotocol/core/issues/{ref}", alias="INTERNAL_TRACKER_URL"
    )
    internal_tracker_faucet_url: str = Field(
        default="https://github.com/xeprotocol/faucet/issues/{ref}", alias="INTERNAL_TRACKER_FAUCET_URL"
    )
    smtp_host: str = Field(default="", alias="SMTP_HOST")
    smtp_port: int = Field(default=587, alias="SMTP_PORT")
    smtp_user: str = Field(default="", alias="SMTP_USER")
    smtp_password: str = Field(default="", alias="SMTP_PASSWORD")
    smtp_from: str = Field(default="desk@xe.network", alias="SMTP_FROM")
    git_commit: str = Field(default=os.environ.get("DESK_GIT_COMMIT", "unknown"), alias="GIT_COMMIT")
    log_level: str = Field(default="info", alias="LOG_LEVEL")
    role: str = Field(default="api", alias="DESK_ROLE")

    @property
    def sync_database_url(self) -> str:
        return self.database_url.replace("+asyncpg", "+psycopg")

    @property
    def blocked_logins(self) -> frozenset[str]:
        return frozenset(x.strip().lower() for x in self.github_blocked_logins.split(",") if x.strip())

    @property
    def discord_bot_enabled(self) -> bool:
        return bool(self.discord_bot_token and self.discord_guild_id and self.discord_support_channel_id)

    @property
    def discord_sign_in(self) -> bool:
        return bool(self.discord_app_id and self.discord_oauth_client_secret)

    @property
    def public_host(self) -> str:
        return urlsplit(self.public_base_url).hostname or "localhost"

    @property
    def scheme(self) -> str:
        return urlsplit(self.public_base_url).scheme or "https"

    @property
    def hosts(self) -> dict[str, str]:
        """Front doors by host name. Both default to the public host when unset (single-host deployment)."""
        return {
            "bounty": self.bounty_host or self.public_host,
            "support": self.support_host or self.public_host,
        }

    @property
    def rp_id(self) -> str:
        """WebAuthn relying-party id: configured, else the registrable suffix shared by the hosts."""
        if self.webauthn_rp_id:
            return self.webauthn_rp_id
        hosts = list(self.hosts.values())
        parts = [h.split(".") for h in hosts]
        common: list[str] = []
        for labels in zip(*[p[::-1] for p in parts]):
            if len(set(labels)) == 1:
                common.append(labels[0])
            else:
                break
        rp = ".".join(reversed(common)) if common else self.public_host
        return rp if rp.count(".") >= 1 or rp == "localhost" else self.public_host

    @property
    def origins(self) -> list[str]:
        """Origins passkeys may be used from: every front door, plus the public base."""
        out = [f"{self.scheme}://{h}" for h in self.hosts.values()]
        base = self.public_base_url.rstrip("/")
        if base not in out:
            out.append(base)
        return out

    @property
    def cookie_domain(self) -> str | None:
        """Sessions span both front doors when they share a registrable suffix (bounty. and support. on
        xe.network); a single host or localhost gets a host-only cookie."""
        if self.hosts["bounty"] == self.hosts["support"]:
            return None
        rp = self.rp_id
        return rp if rp not in self.hosts.values() and rp != "localhost" else None

    def internal_url(self, ref: str) -> str:
        """Link for an internal ticket reference such as `#1064` or `faucet#10`; empty when unconfigured."""
        if not ref:
            return ""
        if ref.startswith("faucet#"):
            tpl = self.internal_tracker_faucet_url
            n = ref.split("#", 1)[1]
        else:
            tpl = self.internal_tracker_url
            n = ref.lstrip("#")
        return tpl.replace("{ref}", n) if tpl and n.isdigit() else ""


@lru_cache
def get_settings() -> Settings:
    return Settings()
