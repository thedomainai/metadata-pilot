#!/usr/bin/env python3
"""
Translate Japanese filenames in docs/00_inbox/ to English.

This script:
1. Scans docs/00_inbox/ for files with Japanese characters
2. Translates filenames to English (using file content context when available)
3. Renames files
4. Updates metadata using osmeta.py
"""

import os
import re
import sys
import subprocess
from pathlib import Path
from typing import Optional, Tuple

# Add parent directory to path to import osmeta utilities
ROOT = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

def has_japanese(text: str) -> bool:
    """Check if text contains Japanese characters"""
    japanese_pattern = re.compile(r'[\u3040-\u309F\u30A0-\u30FF\u4E00-\u9FAF]')
    return bool(japanese_pattern.search(text))

def sanitize_filename(name: str) -> str:
    """Convert to filesystem-safe filename"""
    # Remove or replace problematic characters
    name = re.sub(r'[<>:"/\\|?*]', '-', name)
    name = re.sub(r'\s+', '-', name)
    name = re.sub(r'-+', '-', name)
    name = name.strip('-')
    return name

def translate_filename_with_content(file_path: Path) -> Optional[str]:
    """
    Read file content and generate English filename based on content.
    For now, we'll use a simple approach: read first few lines and suggest translation.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            # Read first 10 lines for context
            lines = [f.readline() for _ in range(10)]
            content_preview = '\n'.join([l for l in lines if l.strip()])
    except Exception:
        content_preview = ""
    
    # Extract base name and extension
    stem = file_path.stem
    ext = file_path.suffix
    
    # For now, return None to indicate manual translation needed
    # In a full implementation, you'd call an LLM API here
    return None

def suggest_english_filename(file_path: Path) -> Optional[str]:
    """
    Suggest English filename based on filename patterns.
    Prioritizes direct filename translations over content-based suggestions.
    """
    # Extract extension
    ext = file_path.suffix
    stem = file_path.stem
    
    # Common translations based on filename patterns (prioritized)
    translations = {
        '組織の動かし方': 'how-to-move-organization',
        'AI活用への自分のアサイン': 'my-assignment-for-ai-adoption',
        'エージェント スキル': 'agent-skills',
        'サブエージェント': 'sub-agent',
        'プラグイン': 'plugin',
        'ヘッドレスモード': 'headless-mode',
        '出力スタイル': 'output-style',
        'プロンプト・エンジニアリングは、まだ始まってすらいない': 'prompt-engineering-has-not-even-started',
        'AIエージェント（Claude CodeCodexCursor）とのチャット履歴を組織のドキュメント資産にするプロンプトrules': 'prompt-rules-for-organizing-chat-history-with-ai-agents',
        '「組織を動かす」動きをアシストしてくれるシステムプロンプト': 'system-prompt-for-assisting-organization-movement',
        'Claude Code フックの使い始め': 'getting-started-with-claude-code-hooks',
        'Claude Code を MCP 経由でツールに接続する': 'connecting-claude-code-to-tools-via-mcp',
        'Cursorで要件定義がエラいスムーズになった話': 'how-cursor-made-requirements-definition-smooth',
        'ChatGPTの記憶システムはRAGを使っていなかった - 4層アーキテクチャの衝撃': 'chatgpt-memory-system-did-not-use-rag-4-layer-architecture-shock',
        '「1人あたり売上」が、すでに大手ECを抜いた話 ーー 2025年AI奮闘記｜門奈剣平': 'revenue-per-person-exceeded-major-ec-2025-ai-struggles',
        'AIを前提としたプロダクトを思考する際のフレーム': 'framework-for-thinking-about-ai-native-products',
        '宇宙はつくることができるという仮説': 'hypothesis-that-universe-can-be-created',
        'pospomeのプログラミング日記': 'pospome-programming-diary',
        'ATSの比較評価': 'ats-comparison-evaluation',
        'ミダス定例_20251219': 'midas-regular-meeting-20251219',
        'wiki-LSのGMV計測': 'wiki-ls-gmv-measurement',
        '経営管理基盤_SWW': 'management-base-sww',
        'ファイル管理最適化ツールの競合調査': 'file-management-optimization-tool-competitive-research',
        '人事制度の外観': 'personnel-system-overview',
        'Obsidian×Cursor共通YAML設計': 'obsidian-cursor-common-yaml-design',
        'セールスBPO事業のコスト構造': 'sales-bpo-business-cost-structure',
        '【株式会社令和】ファイナンス資料_202512': 'reiwa-corporation-finance-materials-202512',
        'Claude Code フックの使い始め': 'getting-started-with-claude-code-hooks',
        'Claude Code を MCP 経由でツールに接続する': 'connecting-claude-code-to-tools-via-mcp',
        'Cursorで要件定義がエラいスムーズになった話': 'how-cursor-made-requirements-definition-smooth',
        'ChatGPTの記憶システムはRAGを使っていなかった - 4層アーキテクチャの衝撃': 'chatgpt-memory-system-did-not-use-rag-4-layer-architecture-shock',
        'プロンプト・エンジニアリングは、まだ始まってすらいない': 'prompt-engineering-has-not-even-started',
        'AIエージェント（Claude CodeCodexCursor）とのチャット履歴を組織のドキュメント資産にするプロンプトrules': 'prompt-rules-for-organizing-chat-history-with-ai-agents',
        '「組織を動かす」動きをアシストしてくれるシステムプロンプト': 'system-prompt-for-assisting-organization-movement',
        'pospomeのプログラミング日記': 'pospome-programming-diary',
        'ミダス定例_20251219': 'midas-regular-meeting-20251219',
        'wiki-LSのGMV計測': 'wiki-ls-gmv-measurement',
    }
    
    # Check if we have a direct translation (exact match)
    if stem in translations:
        return translations[stem] + ext
    
    # Try partial matches (longest match first)
    sorted_keys = sorted(translations.keys(), key=len, reverse=True)
    for key in sorted_keys:
        if key in stem:
            return translations[key] + ext
    
    # If no translation found, try to generate from stem
    # Remove common Japanese patterns and convert to lowercase with hyphens
    # This is a fallback - better to have explicit translations
    return None

def main():
    inbox_dir = Path(ROOT) / "docs" / "00_inbox"
    
    if not inbox_dir.exists():
        print(f"Error: {inbox_dir} does not exist")
        sys.exit(1)
    
    # Find all files with Japanese characters in filename
    japanese_files = []
    for file_path in inbox_dir.iterdir():
        if file_path.is_file():
            if has_japanese(file_path.name):
                japanese_files.append(file_path)
    
    if not japanese_files:
        print("No files with Japanese characters found.")
        return
    
    print(f"Found {len(japanese_files)} files with Japanese characters:\n")
    for i, file_path in enumerate(japanese_files, 1):
        print(f"{i}. {file_path.name}")
    
    print("\n" + "="*60)
    print("Auto-translating Japanese filenames to English...")
    print("="*60 + "\n")
    
    translations = {}
    for file_path in japanese_files:
        print(f"Processing: {file_path.name}")
        
        # Try to suggest translation
        suggested = suggest_english_filename(file_path)
        
        if not suggested:
            print(f"  ⚠ No translation found, skipping: {file_path.name}")
            continue
        
        # Use suggested translation
        english_name = suggested
        translations[file_path] = english_name
        print(f"  → Will rename to: {english_name}")
    
    if not translations:
        print("\nNo files to rename (no translations found).")
        return
    
    # Show summary
    print(f"\n{'='*60}")
    print(f"About to rename {len(translations)} files:")
    for old_path, new_name in translations.items():
        print(f"  {old_path.name}")
        print(f"    → {new_name}")
    print("="*60)
    
    # Perform renames and update metadata
    print("\nRenaming files and updating metadata...")
    for old_path, new_name in translations.items():
        new_path = old_path.parent / new_name
        
        # Check if target exists
        if new_path.exists():
            print(f"Warning: {new_name} already exists. Skipping {old_path.name}")
            continue
        
        try:
            # Rename file
            old_path.rename(new_path)
            print(f"✓ Renamed: {old_path.name} -> {new_name}")
            
            # Update metadata
            old_rel = os.path.relpath(old_path, ROOT)
            new_rel = os.path.relpath(new_path, ROOT)
            
            result = subprocess.run(
                ["python3", "tools/osmeta.py", "rename", old_rel, new_rel],
                cwd=ROOT,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                print(f"  ✓ Metadata updated")
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
        
        except Exception as e:
            print(f"✗ Error renaming {old_path.name}: {e}")
    
    print("\nDone!")

if __name__ == "__main__":
    main()

