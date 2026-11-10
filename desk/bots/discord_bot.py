"""The Discord face of support. A panel in #support with a topic menu; picking one opens a form, the
form opens a private thread and a ticket; the thread is the ticket's public conversation; the team
answers from either side. Runs as its own container (`desk bot-discord`), sharing the database.

Permissions it needs: View Channels, Send Messages, Send Messages in Threads, Create Private Threads,
Manage Threads, Read Message History, Embed Links, Attach Files. Not Administrator. The Message Content
intent must be on, or it cannot read follow-ups in threads.
"""

from __future__ import annotations

import asyncio
import logging
import signal

import discord
from discord import app_commands

from ..context import Context, build_context, set_context
from ..db import session
from ..services import channels as ch
from ..services import thread as thsvc
from ..services.tickets import ticket_url

log = logging.getLogger("desk.discord")
PLATFORM = "discord"
MAX_DISCORD = 1900  # under the 2000-character message limit, with room for a footer


def _chunks(text: str, n: int = MAX_DISCORD) -> list[str]:
    """Split on paragraph breaks to stay under Discord's message limit; a single long paragraph is cut."""
    out, cur = [], ""
    for para in text.split("\n"):
        while len(para) > n:
            if cur:
                out.append(cur)
                cur = ""
            out.append(para[:n])
            para = para[n:]
        if cur and len(cur) + len(para) + 1 > n:
            out.append(cur)
            cur = para
        else:
            cur = f"{cur}\n{para}" if cur else para
    if cur:
        out.append(cur)
    return out or [""]


class AskModal(discord.ui.Modal):
    """The form behind the topic menu. Two fields; the same length rules as the web form."""

    question = discord.ui.TextInput(label="Your question, in one line", max_length=200, required=True)
    details = discord.ui.TextInput(
        label="Details",
        style=discord.TextStyle.paragraph,
        max_length=3000,
        required=False,
        placeholder="What you are trying to do, what happened, anything you have tried. Never a seed or key.",
    )

    def __init__(self, bot: DeskBot, topic: str):
        super().__init__(title=bot.ctx.config.topics.get(topic, "Ask a question")[:45])
        self.bot, self.topic = bot, topic

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            thread_ = await self.bot.open_thread(
                interaction, self.topic, str(self.question), str(self.details)
            )
        except Exception as e:
            log.exception("open failed: %s", e)
            await interaction.followup.send(
                "Could not open the question; the team has been told. Try again in a minute.", ephemeral=True
            )
            return
        await interaction.followup.send(f"Opened {thread_.mention}. Continue there.", ephemeral=True)


class TopicSelect(discord.ui.Select):
    def __init__(self, bot: DeskBot):
        opts = [
            discord.SelectOption(
                label=label[:100], value=key, description=(bot.topic_blurbs.get(key) or "")[:100]
            )
            for key, label in bot.ctx.config.topics.items()
        ]
        super().__init__(custom_id="desk:topic", placeholder="Pick a topic to ask a question", options=opts)
        self.bot = bot

    async def callback(self, interaction: discord.Interaction):
        await interaction.response.send_modal(AskModal(self.bot, self.values[0]))


class PanelView(discord.ui.View):
    def __init__(self, bot: DeskBot):
        super().__init__(timeout=None)  # persistent: survives restarts once add_view() has registered it
        self.add_item(TopicSelect(bot))


class DeskBot(discord.Client):
    def __init__(self, ctx: Context):
        intents = discord.Intents.default()
        intents.message_content = True
        # nothing the bot relays rings @everyone, a role or a user unless a send says so (XE-1115)
        super().__init__(intents=intents, allowed_mentions=discord.AllowedMentions.none())
        self.ctx = ctx
        self.s = ctx.settings
        self.tree = app_commands.CommandTree(self)
        self.guild = discord.Object(id=self.s.discord_guild_id)
        self.topic_blurbs: dict[str, str] = (ctx.config.copy_public.get("support") or {}).get("topics") or {}
        self._mirror_task: asyncio.Task | None = None
        self.commands_ok = False
        self._register_commands()

    # ---- lifecycle -------------------------------------------------------------------------

    async def setup_hook(self):
        self.add_view(PanelView(self))
        self.commands_ok = await self.sync_commands()
        self._mirror_task = asyncio.create_task(self.mirror_loop())

    async def sync_commands(self) -> bool:
        try:
            await self.tree.sync(guild=self.guild)
            return True
        except discord.Forbidden:
            log.error(
                "cannot register slash commands in guild %s (403 Missing Access). Either the bot was invited "
                "without the `applications.commands` scope, or DISCORD_GUILD_ID is not the server it is in. "
                "Re-invite with scopes `bot applications.commands`; the bot keeps running and retries.",
                self.s.discord_guild_id,
            )
            return False

    async def on_ready(self):
        log.info("discord bot up as %s; guild %s", self.user, self.s.discord_guild_id)
        guild = self.get_guild(self.s.discord_guild_id)
        if guild is None:
            log.error("the bot is not in guild %s; check DISCORD_GUILD_ID and the invite", self.s.discord_guild_id)
        else:
            log.info("in %s; support channel %s", guild.name, self.s.discord_support_channel_id)
        if not self.commands_ok:
            self.commands_ok = await self.sync_commands()

    # ---- helpers ---------------------------------------------------------------------------

    def is_team(self, member) -> bool:
        roles = getattr(member, "roles", None) or []
        return any(r.id == self.s.discord_support_role_id for r in roles)

    async def ticket_here(self, interaction: discord.Interaction, db):
        if not isinstance(interaction.channel, discord.Thread):
            raise app_commands.AppCommandError("Use this inside a question's thread.")
        t = await ch.ticket_for(db, PLATFORM, str(interaction.channel.id))
        if t is None:
            raise app_commands.AppCommandError("This thread is not a desk ticket.")
        return t

    def need_team(self, interaction: discord.Interaction):
        if not self.is_team(interaction.user):
            raise app_commands.AppCommandError("That is for the support team.")

    async def support_channel(self) -> discord.TextChannel:
        c = self.get_channel(self.s.discord_support_channel_id) or await self.fetch_channel(
            self.s.discord_support_channel_id
        )
        if not isinstance(c, discord.TextChannel):
            raise RuntimeError("DISCORD_SUPPORT_CHANNEL_ID is not a text channel")
        return c

    async def open_thread(self, interaction: discord.Interaction, topic: str, title: str, details: str):
        channel = await self.support_channel()
        name = f"{title[:80]}"
        try:
            thread_ = await channel.create_thread(
                name=name,
                type=discord.ChannelType.private_thread,
                invitable=False,
                auto_archive_duration=10080,
            )
        except discord.HTTPException:
            # private threads unavailable on this server: a public one, still a thread per question
            thread_ = await channel.create_thread(
                name=name, type=discord.ChannelType.public_thread, auto_archive_duration=10080
            )
        await thread_.add_user(interaction.user)
        async with session() as db:
            post = ch.ChannelPost(
                platform=PLATFORM,
                thread_ref=str(thread_.id),
                thread_url=thread_.jump_url,
                user_id=str(interaction.user.id),
                user_name=interaction.user.display_name,
                user_handle=interaction.user.name,
                title=title,
                body=details,
                topic=topic,
            )
            t = await ch.open_from_channel(self.ctx, db, post)
            created = ch.bot_text(self.ctx, "created", t)
            opened = ch.bot_text(self.ctx, "opened", t, topic=self.ctx.config.topics.get(topic, topic))
            await db.commit()
        try:
            await thread_.edit(name=f"{t.id} · {title}"[:100])
        except discord.HTTPException:
            pass
        role_id = self.s.discord_support_role_id
        role = f"<@&{role_id}> " if role_id else ""
        head = f"{role}{interaction.user.mention} asks, under **{self.ctx.config.topics.get(topic, topic)}**:"
        body = f"**{title}**" + (f"\n{details}" if details else "")
        # only the asker and the support role ring; the member's own text pings nobody (XE-1115)
        allowed = discord.AllowedMentions(
            everyone=False,
            users=[interaction.user],
            roles=[discord.Object(id=int(role_id))] if role_id else False,
            replied_user=False,
        )
        for part in _chunks(f"{head}\n{body}"):
            await thread_.send(part, allowed_mentions=allowed)
        await thread_.send(f"{created}\n{opened}".strip(), allowed_mentions=discord.AllowedMentions.none())
        return thread_

    # ---- messages in threads ---------------------------------------------------------------

    async def on_message(self, message: discord.Message):
        if message.author.bot or not isinstance(message.channel, discord.Thread):
            return
        if message.guild is None or message.guild.id != self.s.discord_guild_id:
            return
        async with session() as db:
            t = await ch.ticket_for(db, PLATFORM, str(message.channel.id))
            if t is None:
                return
            try:
                await ch.incoming(
                    self.ctx,
                    db,
                    t,
                    message_ref=str(message.id),
                    user_id=str(message.author.id),
                    user_name=message.author.display_name,
                    body=message.content,
                    is_team=self.is_team(message.author),
                    attachments=[a.url for a in message.attachments],
                )
                await db.commit()
            except Exception as e:
                log.warning("incoming on %s: %s", t.id, e)

    # ---- desk → discord --------------------------------------------------------------------

    async def mirror_loop(self):
        await self.wait_until_ready()
        n = 0
        while not self.is_closed():
            try:
                await self.mirror_once()
            except Exception as e:
                log.warning("mirror: %s", e)
            n += 1
            if not self.commands_ok and n % 60 == 0:  # every five minutes, until the invite is fixed
                self.commands_ok = await self.sync_commands()
            await asyncio.sleep(5)

    async def _thread(self, ref: str) -> discord.Thread | None:
        c = self.get_channel(int(ref))
        if c is None:
            try:
                c = await self.fetch_channel(int(ref))
            except discord.HTTPException:
                return None
        return c if isinstance(c, discord.Thread) else None

    async def mirror_once(self):
        async with session() as db:
            for r, t in await ch.queued_replies(db, PLATFORM):
                th = await self._thread(t.source_ref)
                if not await ch.writes_to_thread(db, t, r):
                    await db.commit()  # sealed, or taken back, since this pass selected it
                    continue
                if th is None:  # asked first: a reply the seal took back is not marked failed over it
                    await ch.mark_failed(self.ctx, db, r, t, "thread not found")
                    await db.commit()
                    continue
                try:
                    if th.archived:
                        await th.edit(archived=False)
                    last = None
                    for part in _chunks(ch.reply_text(self.ctx, t, r)):
                        # asked again straight before each message: the thread may have had to be
                        # reopened first, and a long reply is several messages
                        if not await ch.writes_to_thread(db, t, r):
                            last = None
                            break
                        last = await th.send(part, suppress_embeds=True)
                    if last is not None:
                        await ch.mark_mirrored(
                            self.ctx, db, r, t, message_ref=str(last.id), url=last.jump_url
                        )
                except discord.HTTPException as e:
                    await ch.mark_failed(self.ctx, db, r, t, str(e))
                await db.commit()
            for t in await ch.needing_state_push(db, PLATFORM):
                th = await self._thread(t.source_ref)
                if th is None:
                    continue
                if not await ch.writes_to_thread(db, t):
                    await db.commit()
                    continue
                want = ch.wanted_state(t)
                if t.channel_state == want:
                    continue  # moved back while the thread was being fetched
                try:
                    if want == "closed":
                        await th.send(ch.closed_line(self.ctx, t))
                        await th.edit(archived=True, locked=True)
                    else:
                        await th.edit(archived=False, locked=False)
                        await th.send(f"Reopened: {t.id} is back with the team.")
                    await ch.mark_state(self.ctx, db, t, want)
                except discord.HTTPException as e:
                    log.warning("state push %s: %s", t.id, e)
                await db.commit()

    # ---- slash commands --------------------------------------------------------------------

    def _register_commands(self):
        tree, guild = self.tree, self.guild

        @tree.error
        async def on_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
            cause = getattr(error, "original", None) or error
            msg = str(getattr(cause, "detail", None) or cause) or "That did not work."
            if not isinstance(cause, app_commands.AppCommandError) and not hasattr(cause, "detail"):
                log.exception("command failed: %s", cause)
            if interaction.response.is_done():
                await interaction.followup.send(msg, ephemeral=True)
            else:
                await interaction.response.send_message(msg, ephemeral=True)

        @tree.command(name="panel", description="Post the support panel here (team only)", guild=guild)
        async def panel(interaction: discord.Interaction):
            self.need_team(interaction)
            sc = self.ctx.config.copy_public.get("support") or {}
            bots = self.ctx.config.copy_public.get("bots") or {}
            embed = discord.Embed(
                title=str(bots.get("panel_title") or sc.get("headline") or "Support"),
                description=str(bots.get("panel_body") or sc.get("sub") or ""),
                colour=discord.Colour.from_str("#ff6900"),
            )
            embed.set_footer(text=f"{sc.get('safety_lead', '')}")
            await interaction.channel.send(embed=embed, view=PanelView(self))
            await interaction.response.send_message("Panel posted.", ephemeral=True)

        @tree.command(name="close", description="Close this question as answered (team only)", guild=guild)
        @app_commands.describe(reason="Optional: a few words; start with 'stale' or 'dup' for those")
        async def close(interaction: discord.Interaction, reason: str = ""):
            self.need_team(interaction)
            async with session() as db:
                t = await self.ticket_here(interaction, db)
                await ch.close_from_channel(self.ctx, db, t, user_id=str(interaction.user.id), reason=reason)
                line = ch.closed_line(self.ctx, t, reason)
                await db.commit()
            await interaction.response.send_message(line)
            await interaction.channel.edit(archived=True, locked=True)

        @tree.command(name="reopen", description="Reopen this question (team only)", guild=guild)
        async def reopen(interaction: discord.Interaction):
            self.need_team(interaction)
            async with session() as db:
                t = await self.ticket_here(interaction, db)
                await ch.reopen_from_channel(self.ctx, db, t, user_id=str(interaction.user.id))
                await db.commit()
            await interaction.channel.edit(archived=False, locked=False)
            await interaction.response.send_message(f"Reopened: {t.id} is back with the team.")

        @tree.command(
            name="bounty", description="A bug, not a question: move it to the bounty (team only)", guild=guild
        )
        async def bounty(interaction: discord.Interaction):
            self.need_team(interaction)
            async with session() as db:
                t = await self.ticket_here(interaction, db)
                await ch.convert_to_bounty(self.ctx, db, t, user_id=str(interaction.user.id))
                line = ch.bot_text(self.ctx, "converted", t)
                await db.commit()
            await interaction.response.send_message(line, suppress_embeds=True)

        @tree.command(name="rename", description="Rename this question (team only)", guild=guild)
        async def rename(interaction: discord.Interaction, title: str):
            self.need_team(interaction)
            async with session() as db:
                t = await self.ticket_here(interaction, db)
                uid = str(interaction.user.id)
                new = await ch.rename_from_channel(self.ctx, db, t, user_id=uid, title=title)
                await db.commit()
            await interaction.channel.edit(name=f"{t.id} · {new}"[:100])
            await interaction.response.send_message(f"Renamed to **{new}**.")

        @tree.command(name="add", description="Bring someone into this thread (team only)", guild=guild)
        async def add(interaction: discord.Interaction, user: discord.Member):
            self.need_team(interaction)
            async with session() as db:
                await self.ticket_here(interaction, db)
            await interaction.channel.add_user(user)
            await interaction.response.send_message(f"Added {user.mention}.")

        names = [n for n in self.ctx.config.reply_templates if n.startswith("support_")]
        choices = [
            app_commands.Choice(name=n.removeprefix("support_").replace("_", " "), value=n) for n in names
        ]

        @tree.command(
            name="answer", description="Post a standard answer, under your name (team only)", guild=guild
        )
        @app_commands.describe(which="The standard answer", text="Your words, for answers that take them")
        @app_commands.choices(which=choices)
        async def answer(interaction: discord.Interaction, which: app_commands.Choice[str], text: str = ""):
            self.need_team(interaction)
            async with session() as db:
                t = await self.ticket_here(interaction, db)
                body = await thsvc.render_template(self.ctx, db, which.value, t, answer=text or "(see above)")
                line = f"**{interaction.user.display_name}** · XE team\n{body}"
                await interaction.response.send_message(line, suppress_embeds=True)
                sent = await interaction.original_response()
                await ch.incoming(
                    self.ctx,
                    db,
                    t,
                    message_ref=str(sent.id),
                    user_id=str(interaction.user.id),
                    user_name=interaction.user.display_name,
                    body=body,
                    is_team=True,
                )
                await db.commit()

        @tree.command(name="ticket", description="Where this thread lives on the desk", guild=guild)
        async def ticket(interaction: discord.Interaction):
            async with session() as db:
                t = await self.ticket_here(interaction, db)
                url = ticket_url(self.ctx, t)
            # anyone in the thread may ask; where a sealed ticket stands is on its page, for those
            # who may open it (XE-0700)
            where = f"{t.id} · {t.status} · {url}" if t.visibility == "public" else f"{t.id} · {url}"
            await interaction.response.send_message(where, ephemeral=True)


async def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    ctx = build_context()
    set_context(ctx)
    if not ctx.settings.discord_bot_enabled:
        log.error("DISCORD_BOT_TOKEN, DISCORD_GUILD_ID, DISCORD_SUPPORT_CHANNEL_ID are needed; not starting")
        return
    bot = DeskBot(ctx)
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(bot.close()))
    try:
        await bot.start(ctx.settings.discord_bot_token)
    except discord.LoginFailure:
        log.error("DISCORD_BOT_TOKEN was rejected; copy it again from the Bot tab")
    except discord.PrivilegedIntentsRequired:
        log.error("turn on the Message Content intent on the Bot tab, then restart")
    finally:
        await bot.close()
        await ctx.aclose()


if __name__ == "__main__":
    asyncio.run(main())
