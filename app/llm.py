import time
import traceback
import logging
from datetime import datetime, timedelta, timezone

from .db import (
    claim_next_pending_job,
    complete_job,
    failure_job,
)


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


def process_job(job):
    attack_prompt = job["attack_prompt"]
    full_defense_prompt = job["full_defense_prompt"]

    result = "echo: " + full_defense_prompt + " " + attack_prompt
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