"""
Safe Telegram Bot (single-file)

Roadmap (how it works)
- Bootstrap
  - Reads TELEGRAM_BOT_TOKEN from environment.
  - Configures basic logging for observability.
- App wiring
  - Builds a python-telegram-bot Application with the token.
  - Registers handlers:
    - /start -> welcome message and brief help
    - /help  -> lists available commands
    - /ping  -> health check
    - Text   -> echoes back what the user said (non-command messages)
  - Registers a global error handler to log uncaught exceptions.
- Runtime
  - Starts polling via run_polling() and processes updates until interrupted.
- Extensibility
  - Add new commands by creating async functions and registering CommandHandler.
  - Add business logic inside handlers; keep I/O (network/db) async.
"""

import os
import logging
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, ContextTypes, filters


logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "Hi! I am a safe Telegram bot template.\n\n"
        "Commands:\n"
        "/start - show welcome message\n"
        "/help - show this help\n"
        "/ping - health check"
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "Available commands:\n"
        "/start - welcome message\n"
        "/help - this help\n"
        "/ping - health check"
    )


async def ping(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text("pong")


async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    incoming = update.message.text or ""
    await update.message.reply_text(f"You said: {incoming}")


async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.exception("Unhandled exception while handling update", exc_info=context.error)


def main() -> None:
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    if not token:
        raise RuntimeError(
            "Please set the TELEGRAM_BOT_TOKEN environment variable to your bot token."
        )

    application = Application.builder().token(token).build()

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("ping", ping))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))

    application.add_error_handler(on_error)

    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()