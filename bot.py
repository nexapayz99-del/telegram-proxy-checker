import asyncio
import io
import logging
import time
from typing import Optional
from aiogram import Bot, Dispatcher, F, Router
from aiogram.filters import Command, CommandObject
from aiogram.types import Message, BufferedInputFile
from config import BOT_TOKEN, CONCURRENCY, TIMEOUT, TEST_URL
from checker import parse_proxy_line, verify_proxy, ProxyItem

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("ProxyCheckerBot")

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()
router = Router()
dp.include_router(router)


@router.message(Command("start", "help"))
async def cmd_start(message: Message):
    help_text = (
        "⚡ <b>High-Speed Proxy Checker Bot</b>\n\n"
        f"• <b>Concurrency:</b> <code>{CONCURRENCY}</code> simultaneous checks\n"
        f"• <b>Timeout:</b> <code>{TIMEOUT}s</code>\n"
        "• <b>Supported Protocols:</b> SOCKS5, SOCKS4, HTTP, HTTPS, MTProto\n\n"
        "📥 <b>How to use:</b>\n"
        "1. Send a <code>.txt</code> file containing your proxies (one per line).\n"
        "2. Or paste proxies directly into the chat.\n\n"
        "🛠 <b>Supported Formats:</b>\n"
        "• <code>ip:port</code> (Auto-detects SOCKS5/4/HTTP/HTTPS)\n"
        "• <code>ip:port:user:pass</code> or <code>user:pass@ip:port</code>\n"
        "• <code>socks5://ip:port</code> (or <code>socks4://</code>, <code>http://</code>, <code>https://</code>)\n"
        "• <code>mtproto://ip:port:secret</code> or <code>tg://proxy?server=...</code>\n\n"
        "💡 <i>Tip: Add a caption like <code>socks5</code>, <code>http</code>, or <code>mtproto</code> to your file to force checking only that protocol for faster results!</i>"
    )
    await message.answer(help_text, parse_mode="HTML")


async def process_proxy_list(message: Message, raw_text: str, forced_proto: Optional[str] = None):
    lines = raw_text.splitlines()
    proxies = []
    seen = set()

    for line in lines:
        item = parse_proxy_line(line, forced_proto=forced_proto)
        if item and item.raw not in seen:
            seen.add(item.raw)
            proxies.append(item)

    if not proxies:
        await message.reply("❌ No valid proxy lines found in your input.")
        return

    total = len(proxies)
    status_msg = await message.reply(
        f"🔍 <b>Starting Proxy Check...</b>\n"
        f"• Total Unique Proxies: <code>{total}</code>\n"
        f"• Concurrency: <code>{CONCURRENCY}</code>\n"
        f"• Mode: <code>{forced_proto.upper() if forced_proto else 'AUTO-DETECT'}</code>",
        parse_mode="HTML"
    )

    semaphore = asyncio.Semaphore(CONCURRENCY)
    start_time = time.perf_counter()

    completed = 0
    working_results = {
        "socks5": [],
        "socks4": [],
        "http": [],
        "https": [],
        "mtproto": []
    }

    async def tracked_verify(p: ProxyItem):
        nonlocal completed
        res = await verify_proxy(p, semaphore, TIMEOUT, TEST_URL)
        completed += 1
        return res

    tasks = [asyncio.create_task(tracked_verify(p)) for p in proxies]

    # Periodically update progress every 3 seconds to avoid Telegram FloodWait
    while completed < total:
        await asyncio.sleep(3)
        if completed >= total:
            break
        elapsed = time.perf_counter() - start_time
        pct = (completed / total) * 100
        try:
            await status_msg.edit_text(
                f"⏳ <b>Checking Proxies...</b> ({pct:.1f}%)\n"
                f"• Checked: <code>{completed}/{total}</code>\n"
                f"• Elapsed: <code>{elapsed:.1f}s</code>",
                parse_mode="HTML"
            )
        except Exception:
            pass

    results = await asyncio.gather(*tasks)
    elapsed_total = time.perf_counter() - start_time

    all_working_lines = []
    for proxy_item, proto, latency in results:
        if proto:
            formatted = proxy_item.format_output(proto, latency)
            working_results[proto].append((latency, formatted))
            all_working_lines.append((latency, formatted))

    # Sort by fastest latency
    all_working_lines.sort(key=lambda x: x[0])
    total_working = len(all_working_lines)
    dead_count = total - total_working

    summary = (
        f"✅ <b>Check Completed in {elapsed_total:.2f}s!</b>\n\n"
        f"📊 <b>Total Tested:</b> <code>{total}</code>\n"
        f"🟢 <b>Working:</b> <code>{total_working}</code>\n"
        f"🔴 <b>Dead:</b> <code>{dead_count}</code>\n\n"
        f"<b>Breakdown by Protocol:</b>\n"
        f"• SOCKS5: <code>{len(working_results['socks5'])}</code>\n"
        f"• SOCKS4: <code>{len(working_results['socks4'])}</code>\n"
        f"• HTTP: <code>{len(working_results['http'])}</code>\n"
        f"• HTTPS: <code>{len(working_results['https'])}</code>\n"
        f"• MTProto: <code>{len(working_results['mtproto'])}</code>"
    )

    try:
        await status_msg.edit_text(summary, parse_mode="HTML")
    except Exception:
        await message.reply(summary, parse_mode="HTML")

    if total_working > 0:
        output_text = "\n".join(line for _, line in all_working_lines)
        file_bytes = output_text.encode("utf-8")
        doc = BufferedInputFile(file_bytes, filename=f"working_proxies_{total_working}.txt")
        await message.reply_document(
            document=doc,
            caption=f"📂 Here are your <b>{total_working}</b> working proxies (sorted by ping).",
            parse_mode="HTML"
        )


def extract_forced_proto(text: Optional[str]) -> Optional[str]:
    if not text:
        return None
    t = text.strip().lower()
    for p in ("socks5", "socks4", "http", "https", "mtproto"):
        if p in t:
            return p
    return None


@router.message(F.document)
async def handle_document(message: Message):
    doc = message.document
    if not doc.file_name.endswith(".txt"):
        await message.reply("⚠️ Please upload a valid <code>.txt</code> file.", parse_mode="HTML")
        return

    if doc.file_size > 15 * 1024 * 1024:
        await message.reply("⚠️ File is too large! Maximum allowed size is 15MB.")
        return

    file_info = await bot.get_file(doc.file_id)
    downloaded = await bot.download_file(file_info.file_path)
    raw_text = downloaded.read().decode("utf-8", errors="ignore")

    forced_proto = extract_forced_proto(message.caption)
    await process_proxy_list(message, raw_text, forced_proto)


@router.message(F.text & ~F.text.startswith("/"))
async def handle_text_proxies(message: Message):
    await process_proxy_list(message, message.text)


async def main():
    logger.info(f"Starting bot with concurrency={CONCURRENCY}, timeout={TIMEOUT}s")
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
