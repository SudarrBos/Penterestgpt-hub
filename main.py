import os
import json
import hashlib
import logging
import asyncio
from datetime import datetime

from aiohttp import web
import aiosqlite
from lxml import etree

from aiogram import Bot, Dispatcher, types
from aiogram.filters import Command
from aiogram.enums import ParseMode
from aiogram.client.default import DefaultBotProperties

from openai import OpenAI

# -----------------------------
# CONFIG
# -----------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("pentest_hub")

TOKEN = os.getenv("TELEGRAM_TOKEN", "").strip()
OPENAI_KEY = os.getenv("OPENAI_API_KEY", "").strip()
PUBLIC_URL = os.getenv("PUBLIC_URL", "").strip().rstrip("/")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "").strip()

PORT = int(os.getenv("PORT", "10000"))
DB_PATH = os.getenv("DB_PATH", "pentest.db")

if not TOKEN:
    raise RuntimeError("TELEGRAM_TOKEN is missing")
if not PUBLIC_URL:
    raise RuntimeError("PUBLIC_URL is missing (e.g. https://your-app.onrender.com)")
if not WEBHOOK_SECRET:
    raise RuntimeError("WEBHOOK_SECRET is missing")

WEBHOOK_PATH = f"/webhook/{WEBHOOK_SECRET}"
WEBHOOK_URL = f"{PUBLIC_URL}{WEBHOOK_PATH}"

# -----------------------------
# BOT + AI
# -----------------------------
bot = Bot(token=TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.MARKDOWN))
dp = Dispatcher()

client = OpenAI(api_key=OPENAI_KEY) if OPENAI_KEY else None

# -----------------------------
# RUN LOCKS (avoid duplicate processing)
# -----------------------------
RUNNING_TARGETS: set[int] = set()
RUNNING_LOCK = asyncio.Lock()

PROCESSED_UPDATES: dict[str, float] = {}  # update_id -> timestamp
PROCESSED_LOCK = asyncio.Lock()
PROCESSED_TTL_SEC = 120.0  # drop duplicates for 2 minutes


# -----------------------------
# DB
# -----------------------------
async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript(
            """
            CREATE TABLE IF NOT EXISTS projects(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_chat_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS targets(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                scope_text TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(project_id) REFERENCES projects(id)
            );

            CREATE TABLE IF NOT EXISTS artifacts(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER NOT NULL,
                kind TEXT NOT NULL,
                filename TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                telegram_file_id TEXT NOT NULL,
                parsed_json TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(target_id) REFERENCES targets(id)
            );

            CREATE TABLE IF NOT EXISTS ai_runs(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER NOT NULL,
                model TEXT NOT NULL,
                output_md TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(target_id) REFERENCES targets(id)
            );
            """
        )
        await db.commit()


async def db_get_or_create_default_project(chat_id: int) -> int:
    now = datetime.utcnow().isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "SELECT id FROM projects WHERE owner_chat_id=? ORDER BY id DESC LIMIT 1",
            (chat_id,),
        )
        row = await cur.fetchone()
        if row:
            return row[0]

        await db.execute(
            "INSERT INTO projects(owner_chat_id, name, created_at) VALUES(?,?,?)",
            (chat_id, "default", now),
        )
        await db.commit()
        cur2 = await db.execute("SELECT last_insert_rowid()")
        return (await cur2.fetchone())[0]


async def db_get_or_create_target(project_id: int, scope_text: str) -> int:
    now = datetime.utcnow().isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO targets(project_id, scope_text, created_at) VALUES(?,?,?)",
            (project_id, scope_text, now),
        )
        await db.commit()
        cur = await db.execute("SELECT last_insert_rowid()")
        return (await cur.fetchone())[0]


async def db_get_last_target(chat_id: int) -> int | None:
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            """
            SELECT t.id
            FROM targets t
            JOIN projects p ON p.id=t.project_id
            WHERE p.owner_chat_id=?
            ORDER BY t.id DESC
            LIMIT 1
            """,
            (chat_id,),
        )
        row = await cur.fetchone()
        return row[0] if row else None


async def db_save_artifact(target_id: int, kind: str, filename: str, file_id: str, blob_bytes: bytes, parsed_json: dict | None):
    sha = hashlib.sha256(blob_bytes).hexdigest()
    now = datetime.utcnow().isoformat()
    parsed = json.dumps(parsed_json, ensure_ascii=False) if parsed_json else None

    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT INTO artifacts(target_id, kind, filename, sha256, telegram_file_id, parsed_json, created_at)
            VALUES(?,?,?,?,?,?,?)
            """,
            (target_id, kind, filename, sha, file_id, parsed, now),
        )
        await db.commit()


async def db_collect_facts(target_id: int) -> dict:
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "SELECT kind, filename, parsed_json FROM artifacts WHERE target_id=? ORDER BY id ASC",
            (target_id,),
        )
        rows = await cur.fetchall()

    facts = {"target_id": target_id, "artifacts": []}
    for kind, filename, parsed_json in rows:
        item = {"kind": kind, "filename": filename}
        if parsed_json:
            try:
                item["data"] = json.loads(parsed_json)
            except Exception:
                item["data"] = {"raw": parsed_json}
        facts["artifacts"].append(item)
    return facts


async def db_save_ai_run(target_id: int, model: str, output_md: str):
    now = datetime.utcnow().isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO ai_runs(target_id, model, output_md, created_at) VALUES(?,?,?,?)",
            (target_id, model, output_md, now),
        )
        await db.commit()


# -----------------------------
# PARSERS
# -----------------------------
def parse_nmap_xml(xml_bytes: bytes) -> dict:
    root = etree.fromstring(xml_bytes)
    hosts = []

    for h in root.findall("host"):
        st_el = h.find("status")
        state = st_el.get("state") if st_el is not None else "unknown"

        addr = None
        for a in h.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                addr = a.get("addr")

        host_obj = {"address": addr, "state": state, "ports": []}

        ports_el = h.find("ports")
        if ports_el is not None:
            for p in ports_el.findall("port"):
                proto = p.get("protocol")
                portid = p.get("portid")
                st = p.find("state")
                pstate = st.get("state") if st is not None else "unknown"

                svc = p.find("service")
                svc_name = svc.get("name") if svc is not None else None
                product = svc.get("product") if svc is not None else None
                version = svc.get("version") if svc is not None else None
                extrainfo = svc.get("extrainfo") if svc is not None else None

                host_obj["ports"].append(
                    {
                        "protocol": proto,
                        "port": int(portid) if portid and portid.isdigit() else portid,
                        "state": pstate,
                        "service": svc_name,
                        "product": product,
                        "version": version,
                        "extra": extrainfo,
                    }
                )

        hosts.append(host_obj)

    return {"tool": "nmap", "hosts": hosts}


def compact_facts_for_ai(facts: dict, max_hosts: int = 20, max_ports_per_host: int = 50) -> dict:
    """
    Prevent huge payloads to the model.
    Keeps first N hosts and first M ports per host.
    """
    out = {"target_id": facts.get("target_id"), "artifacts": []}
    for art in facts.get("artifacts", []):
        if art.get("kind") == "nmap_xml" and isinstance(art.get("data"), dict):
            data = art["data"]
            hosts = data.get("hosts", [])
            slim_hosts = []
            for h in hosts[:max_hosts]:
                ports = h.get("ports", [])[:max_ports_per_host]
                slim_hosts.append({**h, "ports": ports})
            slim = {"tool": "nmap", "hosts": slim_hosts, "note": f"trimmed to {max_hosts} hosts, {max_ports_per_host} ports/host"}
            out["artifacts"].append({"kind": art.get("kind"), "filename": art.get("filename"), "data": slim})
        else:
            # keep only minimal metadata for unknown artifacts
            out["artifacts"].append({"kind": art.get("kind"), "filename": art.get("filename")})
    return out


# -----------------------------
# AI ANALYSIS (defensive report mode)
# -----------------------------
def ai_analyze_facts(facts: dict):
    if client is None:
        return "⚠️ OPENAI_API_KEY не заданий. AI аналіз недоступний.", "none"

    system = (
        "You are a cybersecurity assessment assistant producing professional defensive reports. "
        "Use the provided scan facts to identify exposure, likely risks, and prioritized remediation. "
        "Do NOT provide step-by-step exploitation instructions, payloads, or hacking guidance. "
        "Focus on verification steps, configuration hardening, patching, and monitoring. "
        "Return Markdown with: Executive Summary, Key Findings (prioritized), Recommended Remediation, Next Validation Steps."
    )

    model = "gpt-4o-mini"
    resp = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": f"Facts JSON:\n{json.dumps(facts, ensure_ascii=False)}"},
        ],
        temperature=0.3,
    )
    return resp.choices[0].message.content, model


# -----------------------------
# TELEGRAM COMMANDS
# -----------------------------
@dp.message(Command("start"))
async def cmd_start(message: types.Message):
    await message.answer(
        "🦾 *PENTESTGPT HUB*\n"
        "• `/scope <text>` — задай scope (домен/URL/опис)\n"
        "• Надішли nmap.xml (або XML із `<nmaprun>` — навіть якщо файл .txt)\n"
        "• `/analyze` — AI зробить звіт\n"
    )


@dp.message(Command("scope"))
async def cmd_scope(message: types.Message):
    chat_id = message.chat.id
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2:
        await message.answer("Використання: `/scope example.com або опис scope`")
        return

    scope_text = parts[1].strip()
    pid = await db_get_or_create_default_project(chat_id)
    tid = await db_get_or_create_target(pid, scope_text)
    await message.answer(f"✅ Scope зафіксовано. Target ID: `{tid}`\nТепер надішли артефакти (наприклад nmap.xml).")


@dp.message(Command("analyze"))
async def cmd_analyze(message: types.Message):
    chat_id = message.chat.id
    tid = await db_get_last_target(chat_id)
    if not tid:
        await message.answer("Спочатку задай scope: `/scope ...`")
        return

    # Avoid duplicate analyses
    async with RUNNING_LOCK:
        if tid in RUNNING_TARGETS:
            await message.answer("⏳ Аналіз уже йде. Я допишу звіт і повернусь.")
            return
        RUNNING_TARGETS.add(tid)

    try:
        facts = await db_collect_facts(tid)
        facts = compact_facts_for_ai(facts)

        await message.answer("🧠 Аналізую артефакти та готую звіт…")

        output_md, model = await asyncio.to_thread(ai_analyze_facts, facts)
        await db_save_ai_run(tid, model, output_md)

        if len(output_md) <= 3500:
            await message.answer(output_md)
        else:
            data = output_md.encode("utf-8")
            doc = types.BufferedInputFile(data, filename=f"report_target_{tid}.md")
            await message.answer_document(doc)

    except Exception as e:
        logger.exception("Analyze failed: %s", e)
        await message.answer(f"⚠️ Помилка під час аналізу: {type(e).__name__}: {e}")

    finally:
        async with RUNNING_LOCK:
            RUNNING_TARGETS.discard(tid)


# -----------------------------
# FILE UPLOAD HANDLER
# -----------------------------
@dp.message()
async def handle_docs(message: types.Message):
    if not message.document:
        return

    chat_id = message.chat.id
    tid = await db_get_last_target(chat_id)
    if not tid:
        await message.answer("Спочатку задай scope: `/scope ...`")
        return

    doc = message.document
    filename = doc.file_name or "artifact.bin"
    file_id = doc.file_id

    tg_file = await bot.get_file(file_id)
    content = await bot.download_file(tg_file.file_path)
    blob = content.read()

    kind = "unknown"
    parsed = None

    # Parse nmap by CONTENT (works even if filename ends with .txt)
    if b"<nmaprun" in blob[:12000]:
        kind = "nmap_xml"
        try:
            parsed = parse_nmap_xml(blob)
        except Exception as e:
            logger.exception("Nmap parse failed: %s", e)
            await message.answer(f"⚠️ Не зміг розпарсити nmap.xml: {type(e).__name__}: {e}")
            parsed = None

    await db_save_artifact(tid, kind, filename, file_id, blob, parsed)

    if kind == "nmap_xml" and parsed:
        hosts = parsed.get("hosts", [])
        await message.answer(f"✅ Прийняв `{filename}` (nmap). Хостів: *{len(hosts)}*. Можеш: `/analyze`")
    else:
        await message.answer(f"✅ Прийняв `{filename}` як `{kind}`. Можеш: `/analyze`")


# -----------------------------
# WEB SERVER (Render)
# -----------------------------
async def on_startup(app: web.Application):
    await init_db()
    await bot.set_webhook(WEBHOOK_URL, drop_pending_updates=True)
    logger.info(f"Webhook set to: {WEBHOOK_URL}")


async def on_shutdown(app: web.Application):
    await bot.delete_webhook()
    await bot.session.close()


async def healthcheck(request):
    return web.Response(text="PENTESTGPT HUB OK")


async def _cleanup_processed():
    # Periodically clean old update ids
    while True:
        await asyncio.sleep(30)
        now = asyncio.get_running_loop().time()
        async with PROCESSED_LOCK:
            dead = [k for k, ts in PROCESSED_UPDATES.items() if (now - ts) > PROCESSED_TTL_SEC]
            for k in dead:
                PROCESSED_UPDATES.pop(k, None)


async def telegram_webhook(request):
    """
    FAST ACK webhook: return 200 immediately, process update in background.
    Also drops duplicate updates (Telegram retry storms).
    """
    try:
        data = await request.json()

        # Deduplicate by update_id if present
        update_id = data.get("update_id")
        now = asyncio.get_running_loop().time()
        if update_id is not None:
            async with PROCESSED_LOCK:
                ts = PROCESSED_UPDATES.get(str(update_id))
                if ts is not None and (now - ts) < PROCESSED_TTL_SEC:
                    return web.Response(status=200, text="OK")
                PROCESSED_UPDATES[str(update_id)] = now

        update = types.Update(**data)

        async def runner():
            try:
                await dp.feed_update(bot, update)
            except Exception as e:
                logger.exception("Update processing failed: %s", e)

        asyncio.create_task(runner())

    except Exception as e:
        logger.exception("Webhook error: %s", e)

    return web.Response(status=200, text="OK")


def make_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/", healthcheck)
    app.router.add_post(WEBHOOK_PATH, telegram_webhook)

    app.on_startup.append(on_startup)
    app.on_shutdown.append(on_shutdown)

    # start cleanup task
    async def start_bg(app_: web.Application):
        app_["cleanup_task"] = asyncio.create_task(_cleanup_processed())

    async def stop_bg(app_: web.Application):
        t = app_.get("cleanup_task")
        if t:
            t.cancel()

    app.on_startup.append(start_bg)
    app.on_shutdown.append(stop_bg)

    return app


if __name__ == "__main__":
    app = make_app()
    web.run_app(app, host="0.0.0.0", port=PORT)