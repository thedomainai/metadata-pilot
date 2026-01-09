# Inbox バッチ処理システム

inbox内の全ファイルに対して、os_meta/に定義された処理を一括実行するシステムです。

## 概要

`tools/process_inbox_batch.py` は、以下の処理を順次実行します：

1. **メタデータの作成・更新**
   - 全inboxファイルに対して `osmeta.py update` を実行
   - ファイル名からタイトルを自動抽出（既に実装済み）
   - メタデータのバリデーション

2. **ファイルの整理**
   - `organize_inbox.py` を実行
   - 適切なディレクトリへ自動移動
   - メタデータも自動更新

## 実行方法

### 手動実行

```bash
# 1日の終わりなど、任意のタイミングで実行
python3 tools/process_inbox_batch.py
```

### 定期実行（cron）

1日の終わりに自動実行する場合：

```bash
# crontabを編集
crontab -e

# 毎日23:00に実行する場合（例）
0 23 * * * cd /Users/lemmaitt/workspace/obsidian_vault && /usr/bin/python3 tools/process_inbox_batch.py >> ~/logs/inbox_batch.log 2>&1
```

### 定期実行（launchd - macOS）

macOSでは `launchd` を使用することもできます：

```bash
# plistファイルを作成
cat > ~/Library/LaunchAgents/com.obsidian.inbox-batch.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.obsidian.inbox-batch</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>/Users/lemmaitt/workspace/obsidian_vault/tools/process_inbox_batch.py</string>
    </array>
    <key>WorkingDirectory</key>
    <string>/Users/lemmaitt/workspace/obsidian_vault</string>
    <key>StartCalendarInterval</key>
    <dict>
        <key>Hour</key>
        <integer>23</integer>
        <key>Minute</key>
        <integer>0</integer>
    </dict>
    <key>StandardOutPath</key>
    <string>/Users/lemmaitt/logs/inbox_batch.log</string>
    <key>StandardErrorPath</key>
    <string>/Users/lemmaitt/logs/inbox_batch_error.log</string>
</dict>
</plist>
EOF

# launchdに登録
launchctl load ~/Library/LaunchAgents/com.obsidian.inbox-batch.plist
```

## 実行される処理の詳細

### 1. メタデータ処理

各inboxファイルに対して：
- `osmeta.py update` でメタデータを作成/更新
- ファイル名から `text_title` を自動抽出
- ディレクトリパスから `content_origin` を自動推論
- スキーマ・ボキャブラリ・ポリシールールに基づくバリデーション

### 2. ファイル整理

`organize_inbox.py` によって：
- ファイル名パターンに基づく分類
- 適切なディレクトリへの移動
  - `docs/01_resource/` - リソースファイル
  - `docs/01_resource/ai/` - AI関連ドキュメント
  - `docs/01_resource/business/` - ビジネス関連
  - `docs/03_project/` - プロジェクト固有ファイル
- 移動後のメタデータ自動更新

## 実行例

```bash
$ python3 tools/process_inbox_batch.py

======================================================================
OS Meta Batch Processing for Inbox Files
======================================================================

Step 1: Found 7 files in inbox

Step 2: Processing metadata (create/update + title extraction)...
----------------------------------------------------------------------
[1/7] ✓ docs/00_inbox/check-in.md
[2/7] ✓ docs/00_inbox/framework.md
[3/7] ✓ docs/00_inbox/llm-debug-cli-lapper.md
[4/7] ✓ docs/00_inbox/sales-pipeline-cyreco.md
[5/7] ✓ docs/00_inbox/tasks.md
[6/7] ✓ docs/00_inbox/tasks-now.md
[7/7] ✓ docs/00_inbox/upselling-existing-customers-and-ai.md

Metadata processing: 7 succeeded, 0 failed

======================================================================
Step 3: Organizing files (moving to appropriate directories)...
----------------------------------------------------------------------
Found 7 files in inbox.

File organization plan:
  check-in.md
    → docs/03_project/00_personal/check-in.md
  ...
✓ File organization completed

======================================================================
Batch processing complete!
======================================================================

✓ Inbox is now empty - all files have been processed and organized
```

## 注意事項

- 実行には数分かかる場合があります（ファイル数による）
- ファイル移動は不可逆です（移動先に既存ファイルがある場合はスキップされます）
- エラーが発生しても処理は継続されます
- ログを確認して、エラーがないかチェックしてください

## トラブルシューティング

### メタデータ処理でエラーが発生する場合

```bash
# 個別に確認
python3 tools/osmeta.py check "docs/00_inbox/問題のファイル.md"
```

### ファイルが移動されない場合

- `organize_inbox.py` の分類ルールを確認
- 移動先ディレクトリの権限を確認
- ログメッセージを確認

### 処理が途中で止まる場合

- タイムアウト設定を確認（デフォルト: メタデータ10秒、整理300秒）
- 大量のファイルがある場合は分割実行を検討

