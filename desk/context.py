"""Process-wide context: settings, config, signer, vault, node client, event log, node identity."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from xe.client import XeClient

from .config import Config, load_config
from .log import EventLog
from .settings import Settings, get_settings
from .signer import Signer, SignerError
from .vault import Vault

log = logging.getLogger("desk")


@dataclass
class NodeIdentity:
    network_id: str = ""
    node_id: str = ""
    version: str = ""

    @property
    def is_mainnet(self) -> bool:
        """Positive match only: `mainnet` or `mainnet-<n>`. Anything else is shown as testnet."""
        return self.network_id.split("-", 1)[0] == "mainnet"

    @property
    def badge(self) -> str:
        return "mainnet" if self.is_mainnet else "testnet"


@dataclass
class Context:
    settings: Settings
    config: Config
    signer: Signer
    vault: Vault
    chain: XeClient
    events: EventLog
    node: NodeIdentity = field(default_factory=NodeIdentity)

    async def refresh_node(self) -> NodeIdentity:
        try:
            info = await self.chain.node()
            if not isinstance(info, dict):
                raise TypeError(f"node answered with {type(info).__name__}, not an object")
        except Exception as e:  # node unreachable at boot is survivable; the desk reads, it never writes
            log.warning("node unreachable: %s", e)
            return self.node

        def text(k: str) -> str:  # a string whatever the node sent (XE-0983)
            v = info.get(k, "")
            return v[:128] if isinstance(v, str) else ""

        self.node = NodeIdentity(network_id=text("network_id"), node_id=text("id"), version=text("version"))
        return self.node

    async def aclose(self) -> None:
        await self.chain.aclose()


_ctx: Context | None = None


def build_context() -> Context:
    settings = get_settings()
    config = load_config(settings.config_dir)
    try:
        signer = Signer.load(settings.signer_keyfile, settings.signer_passphrase)
    except SignerError as e:
        log.warning("signer unavailable (%s); log entries will be unsigned and private content refused", e)
        signer = Signer.empty()
    chain = XeClient(settings.xe_node_url)
    return Context(
        settings=settings,
        config=config,
        signer=signer,
        vault=Vault(signer),
        chain=chain,
        events=EventLog(signer),
    )


def get_context() -> Context:
    global _ctx
    if _ctx is None:
        _ctx = build_context()
    return _ctx


def set_context(ctx: Context) -> None:
    global _ctx
    _ctx = ctx
