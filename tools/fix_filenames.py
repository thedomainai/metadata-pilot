#!/usr/bin/env python3
"""
Fix incorrectly renamed files in docs/00_inbox/
This script corrects files that were renamed to content-based titles instead of proper English translations.
"""

import os
import subprocess
from pathlib import Path

ROOT = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))

# Mapping of current (incorrect) names to correct English names
FIXES = {
    'ai-powered-productとは.md': 'framework-for-ai-native-product-thinking.md',
    '前提条件.md': 'agent-skills.md',
    '仮説.md': 'hypothesis-that-universe-can-be-created.md',
    'クイックスタート.md': 'plugin.md',
    'サブエージェントとは？.md': 'sub-agent.md',
    'qiita-careers-powered-by-indeedpr.md': None,  # Will be handled separately
    'pospomeが普段やってる新しい技術の勉強方法.md': 'pospome-programming-diary.md',
    '本ドキュメントで達成されるべきこと': 'wiki-ls-gmv-measurement.md',
    '概要.md': 'headless-mode.md',
    'このドキュメントは何か.md': 'how-to-move-organization.md',
    'フックイベント概要.md': 'getting-started-with-claude-code-hooks.md',
    '組み込み出力スタイル.md': 'output-style.md',
    '参照元.md': 'chatgpt-memory-system-did-not-use-rag-4-layer-architecture-shock.md',
    'mcp-でできること.md': 'connecting-claude-code-to-tools-via-mcp.md',
    '達成されるべきこと.md': 'my-assignment-for-ai-adoption.md',
    'aiファーストについて': 'midas-regular-meeting-20251219.md',
}

# Files that need to be renamed from qiita-careers-powered-by-indeedpr.md
QIITA_FIXES = {
    'プロンプト・エンジニアリングは、まだ始まってすらいない.md': 'prompt-engineering-has-not-even-started.md',
    '「組織を動かす」動きをアシストしてくれるシステムプロンプト.md': 'system-prompt-for-assisting-organization-movement.md',
    'AIエージェント（Claude CodeCodexCursor）とのチャット履歴を組織のドキュメント資産にするプロンプトrules.md': 'prompt-rules-for-organizing-chat-history-with-ai-agents.md',
    'Cursorで要件定義がエラいスムーズになった話.md': 'how-cursor-made-requirements-definition-smooth.md',
}

def main():
    inbox_dir = Path(ROOT) / "docs" / "00_inbox"
    
    print("Fixing incorrectly renamed files...\n")
    
    # First, handle the qiita-careers file
    qiita_file = inbox_dir / 'qiita-careers-powered-by-indeedpr.md'
    if qiita_file.exists():
        # Read content to determine which file it should be
        try:
            with open(qiita_file, 'r', encoding='utf-8') as f:
                content = f.read(1000)
            
            # Try to match content to determine correct name
            # This is a heuristic - you may need to manually check
            print(f"Found qiita-careers-powered-by-indeedpr.md")
            print("Content preview:")
            print(content[:200])
            print("\nThis file needs manual inspection to determine correct name.")
            print("Skipping for now - please handle manually.\n")
        except Exception as e:
            print(f"Error reading {qiita_file}: {e}\n")
    
    # Fix other files
    fixed_count = 0
    for current_name, correct_name in FIXES.items():
        if correct_name is None:
            continue
            
        current_path = inbox_dir / current_name
        if not current_path.exists():
            continue
        
        correct_path = inbox_dir / correct_name
        
        # Check if target already exists
        if correct_path.exists() and correct_path != current_path:
            print(f"⚠ Target already exists: {correct_name}")
            print(f"  Skipping: {current_name}\n")
            continue
        
        try:
            # Rename file
            current_path.rename(correct_path)
            print(f"✓ Renamed: {current_name} -> {correct_name}")
            
            # Update metadata
            old_rel = os.path.relpath(current_path, ROOT)
            new_rel = os.path.relpath(correct_path, ROOT)
            
            result = subprocess.run(
                ["python3", "tools/osmeta.py", "rename", old_rel, new_rel],
                cwd=ROOT,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                print(f"  ✓ Metadata updated")
                fixed_count += 1
            else:
                print(f"  ⚠ Metadata update warning: {result.stderr}")
            
            # Check metadata
            result = subprocess.run(
                ["python3", "tools/osmeta.py", "check", new_rel],
                cwd=ROOT,
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                print(f"  ⚠ Metadata check warning: {result.stderr}")
            
            print()
        
        except Exception as e:
            print(f"✗ Error renaming {current_name}: {e}\n")
    
    print(f"Fixed {fixed_count} files.")
    print("\nNote: qiita-careers-powered-by-indeedpr.md needs manual handling.")
    print("Please check the file content and rename it to the appropriate name.")

if __name__ == "__main__":
    main()

