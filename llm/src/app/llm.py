from pathlib import Path
import time
import os
import traceback
import logging
from datetime import datetime, timedelta, timezone
from groq import Groq

from .db import (
    claim_next_pending_job,
    complete_job,
    failure_job,
)
from .loadenv import load_env
load_env()


class ISOTimeFormatter(logging.Formatter):
    def formatTime(self, record: logging.LogRecord, datefmt=None):
        tz_jst = timezone(timedelta(hours=+9), 'JST')
        ct = datetime.fromtimestamp(record.created, tz=tz_jst)
        s = ct.isoformat(timespec="microseconds")

        return s


logger = logging.getLogger()
fmt = ISOTimeFormatter("[%(asctime)s] %(message)s")
sh = logging.StreamHandler()
sh.setFormatter(fmt)
logger.addHandler(sh)
logger.setLevel(logging.INFO)

assert os.getenv("GROQ_API_KEY"), "GROQ_API_KEY is not set in environment variables"
client = Groq(api_key=os.getenv("GROQ_API_KEY"))


def process_job(job):
    attack_prompt = job["attack_prompt"]
    full_defense_prompt = job["full_defense_prompt"]

    completion = client.chat.completions.create(
        model="llama-3.1-8b-instant",
        messages=[
            {"role": "system", "content": full_defense_prompt},
            {"role": "user", "content": attack_prompt}
        ],
        max_completion_tokens=1000,
    )
    logger.info(completion)
    result = completion.choices[0].message.content.strip()
    complete_job(job["id"], result)


def main():
    logger.info("LLM worker started")

    while True:
        job = claim_next_pending_job()

        if not job:
            time.sleep(1)
            continue

        try:
            job = dict(job)
            logger.info(f"processing job {job['id']}")
            logger.info(job)
            process_job(job)
        except Exception:
            err = traceback.format_exc()
            logger.error(err)
            failure_job(job["id"], "Runtime Error", err)
        logger.info(f"finished job {job['id']}")


if __name__ == "__main__":
    main()