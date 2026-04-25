# LLM CTF (Attack & Defense) - MVP

FastAPI + Jinja2 + SQLite で動く、10ユーザー固定のシンプルな CTF 運営用プロトタイプです。

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## Demo accounts

- Players: `user01/pass01` ... `user10/pass10`
- Admin: `admin/adminpass`

## MVP flow

1. Admin が `/admin` から `新規フェーズ開始` を押す（state=defense）
2. 各 user が `/defense/edit` で system prompt本文を編集
3. 各 user が `/defense/test` でテスト
4. Admin が `Defense → Attack` を押す
5. 各 user が `/attack` で他ユーザーを攻撃
6. Admin が `フェーズ終了` を押す
7. `/review` で攻撃ログ・システムプロンプト開示

## Notes

- flag はサーバー側固定 prefix として毎 phase ごとにユーザー別再生成されます。
- 現在の LLM 応答は `app/llm.py` のスタブ実装です。実プロバイダ連携はここを差し替えてください。
- 本番運用時は secret key / password 管理 / HTTPS / rate limit などを強化してください。
