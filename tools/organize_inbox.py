#!/usr/bin/env python3
"""
Organize files from docs/00_inbox/ to appropriate directories.

Classification rules:
- docs/01_resource/ - Technical docs, references, external articles (SOURCE)
- docs/03_project/ - Project-specific docs, meeting notes, business docs (DERIVED)
- docs/02_derived/ - Processed/derived documents (DERIVED)
"""

import os
import subprocess
from pathlib import Path
from typing import Optional, Tuple

ROOT = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))

# Forbidden directories (development projects that may be pushed to GitHub)
FORBIDDEN_DIRECTORIES = [
    'docs/03_project/00_thedomainai',
]

def is_forbidden_directory(target_dir: str) -> bool:
    """Check if target directory is forbidden (development project with git)"""
    target_path = Path(ROOT) / target_dir
    
    # Check if directory is in forbidden list
    for forbidden in FORBIDDEN_DIRECTORIES:
        if target_dir.startswith(forbidden):
            return True
    
    # Check if directory contains .git subdirectory
    if (target_path / '.git').exists():
        return True
    
    # Check parent directories for .git
    for parent in target_path.parents:
        if (parent / '.git').exists():
            # If we're inside a git repo, check if it's a development project
            if '00_thedomainai' in str(parent):
                return True
    
    return False

# Classification rules based on filename patterns
CLASSIFICATION_RULES = {
    # Technical documentation -> 01_resource/ai/
    'agent-skills.md': ('01_resource/ai', 'agent-skills.md'),
    'sub-agent.md': ('01_resource/ai', 'sub-agent.md'),
    'getting-started-with-claude-code-hooks.md': ('01_resource/ai', 'getting-started-with-claude-code-hooks.md'),
    'connecting-claude-code-to-tools-via-mcp.md': ('01_resource/ai', 'connecting-claude-code-to-tools-via-mcp.md'),
    'Claude Code GitHub Actions.md': ('01_resource/ai', 'claude-code-github-actions.md'),
    'Claude Code GitLab CICD.md': ('01_resource/ai', 'claude-code-gitlab-cicd.md'),
    'headless-mode.md': ('01_resource/ai', 'headless-mode.md'),
    'output-style.md': ('01_resource/ai', 'output-style.md'),
    'plugin.md': ('01_resource/ai', 'plugin.md'),
    'prompt-engineering-has-not-even-started.md': ('01_resource/ai', 'prompt-engineering-has-not-even-started.md'),
    'prompt-rules-for-organizing-chat-history-with-ai-agents.md': ('01_resource/ai', 'prompt-rules-for-organizing-chat-history-with-ai-agents.md'),
    'system-prompt-for-assisting-organization-movement.md': ('01_resource/ai', 'system-prompt-for-assisting-organization-movement.md'),
    'how-cursor-made-requirements-definition-smooth.md': ('01_resource/ai', 'how-cursor-made-requirements-definition-smooth.md'),
    'chatgpt-memory-system-did-not-use-rag-4-layer-architecture-shock.md': ('01_resource/ai', 'chatgpt-memory-system-did-not-use-rag-4-layer-architecture-shock.md'),
    'ai-autonomous-release-compass.md': ('01_resource/ai', 'ai-autonomous-release-compass.md'),
    'framework-for-ai-native-product-thinking.md': ('01_resource/ai', 'framework-for-ai-native-product-thinking.md'),
    
    # Business/Product articles -> 01_resource/business/
    'revenue-per-person-exceeded-major-ec-2025-ai-struggles.md': ('01_resource/business', 'revenue-per-person-exceeded-major-ec-2025-ai-struggles.md'),
    'file-management-optimization-tool-competitive-research.gdoc': ('01_resource/business', 'file-management-optimization-tool-competitive-research.gdoc'),
    'sales-bpo-business-cost-structure.gdoc': ('01_resource/business', 'sales-bpo-business-cost-structure.gdoc'),
    'SalesBPO M&A.gdoc': ('01_resource/business', 'sales-bpo-ma.gdoc'),
    
    # Personal/Organization -> 03_project/00_personal/ or 01_resource/
    'how-to-move-organization.md': ('01_resource/business', 'how-to-move-organization.md'),
    'my-assignment-for-ai-adoption.md': ('03_project/00_personal', 'my-assignment-for-ai-adoption.md'),
    'framework.md': ('03_project/00_personal', 'framework.md'),
    'hypothesis-that-universe-can-be-created.md': ('01_resource/philosophy', 'hypothesis-that-universe-can-be-created.md'),
    
    # Project-specific -> 03_project/
    'midas-regular-meeting-20251219.md': ('03_project/01_cyreco', 'midas-regular-meeting-20251219.md'),
    'wiki-ls-gmv-measurement.md': ('03_project/01_cyreco', 'wiki-ls-gmv-measurement.md'),
    'management-base-sww.gsheet': ('03_project/01_cyreco', 'management-base-sww.gsheet'),
    'reiwa-corporation-finance-materials-202512.gdoc': ('03_project/02_reiwa', 'reiwa-corporation-finance-materials-202512.gdoc'),
    'personnel-system-overview.gslides': ('03_project/01_cyreco', 'personnel-system-overview.gslides'),
    'sales-pipeline-cyreco.md': ('03_project/01_cyreco', 'sales-pipeline-cyreco.md'),
    
    # Technical/Programming -> 01_resource/
    'pospome-programming-diary.md': ('01_resource', 'pospome-programming-diary.md'),
    'llm-debug-cli-lapper.md': ('01_resource/ai', 'llm-debug-cli-lapper.md'),
    'Connect to your database.md': ('01_resource/ai', 'connect-to-your-database.md'),
    
    # Templates/References -> 01_resource/ or keep in inbox
    'presentation_template.md': ('01_resource', 'presentation_template.md'),
    'presentation_template.yaml': ('01_resource', 'presentation_template.yaml'),
    'Introduction.md': ('01_resource', 'introduction.md'),
    '10essentials.md': ('01_resource', '10essentials.md'),
    
    # About me -> 03_project/00_personal/
    'about-me-nakabayashi.md': ('03_project/00_personal', 'about-me-nakabayashi.md'),
    'about-me-nakabayashi-attract.md': ('03_project/00_personal', 'about-me-nakabayashi-attract.md'),
    
    # Evaluation/Assessment -> 01_resource/business/
    'ats-comparison-evaluation.md': ('01_resource/business', 'ats-comparison-evaluation.md'),
    
    # Other technical -> 01_resource/
    'data-for-ai': ('01_resource/ai', 'data-for-ai'),
    'sales-practice-pragmatics': ('01_resource/business', 'sales-practice-pragmatics'),
    'tiktopshop-whitepaper': ('01_resource/business', 'tiktopshop-whitepaper'),
    'mvvc-equitystory-gap.md': ('01_resource/business', 'mvvc-equitystory-gap.md'),
    'Thread by @MiraiSeed_jp.md': ('01_resource/business', 'thread-by-miraiseed-jp.md'),
    'Split image online.md': ('01_resource', 'split-image-online.md'),
    'three.js css3d - periodic table.md': ('01_resource', 'three-js-css3d-periodic-table.md'),
    'Manthan.md': ('01_resource', 'manthan.md'),
    'obsidian-cursor-common-yaml-design.gdoc': ('01_resource', 'obsidian-cursor-common-yaml-design.gdoc'),
    'upselling-existing-customers-and-ai.md': ('01_resource/business', 'upselling-existing-customers-and-ai.md'),
    'check-in.md': ('03_project/00_personal', 'check-in.md'),
}

def classify_file(file_path: Path) -> Optional[Tuple[str, str]]:
    """Classify a file and return (target_dir, target_filename) or None"""
    filename = file_path.name
    
    # Direct match
    if filename in CLASSIFICATION_RULES:
        return CLASSIFICATION_RULES[filename]
    
    # Pattern matching (fallback)
    filename_lower = filename.lower()
    
    # AI/Technical patterns
    if any(keyword in filename_lower for keyword in ['claude', 'cursor', 'agent', 'prompt', 'ai-', '-ai']):
        return ('01_resource/ai', filename)
    
    # Project patterns
    if any(keyword in filename_lower for keyword in ['cyreco', 'reiwa', 'midas', 'meeting', '定例']):
        if 'cyreco' in filename_lower or 'midas' in filename_lower:
            return ('03_project/01_cyreco', filename)
        elif 'reiwa' in filename_lower:
            return ('03_project/02_reiwa', filename)
    
    # Business patterns
    if any(keyword in filename_lower for keyword in ['sales', 'bpo', 'business', 'cost', 'structure']):
        return ('01_resource/business', filename)
    
    # Default: keep in resource
    return ('01_resource', filename)

def main():
    inbox_dir = Path(ROOT) / "docs" / "00_inbox"
    
    if not inbox_dir.exists():
        print(f"Error: {inbox_dir} does not exist")
        return
    
    # Get all files in inbox
    files = [f for f in inbox_dir.iterdir() if f.is_file()]
    
    if not files:
        print("No files found in inbox.")
        return
    
    print(f"Found {len(files)} files in inbox.\n")
    print("="*60)
    print("File organization plan:")
    print("="*60 + "\n")
    
    moves = []
    skipped_forbidden = []
    
    for file_path in sorted(files):
        classification = classify_file(file_path)
        if classification:
            target_dir, target_filename = classification
            full_target_dir = f"docs/{target_dir}"
            
            # Check if target directory is forbidden (development project)
            if is_forbidden_directory(full_target_dir):
                skipped_forbidden.append((file_path.name, full_target_dir))
                print(f"  ⚠ SKIPPED (forbidden dev directory): {file_path.name}")
                print(f"    Would move to: {full_target_dir}/{target_filename}")
                print(f"    Reason: Development project directory (may be pushed to GitHub)")
                continue
            
            target_path = Path(ROOT) / "docs" / target_dir / target_filename
            
            # Create target directory if needed
            target_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Check if target exists
            if target_path.exists() and target_path != file_path:
                print(f"⚠ Target exists, skipping: {file_path.name} -> {target_dir}/{target_filename}")
                continue
            
            moves.append((file_path, target_path, target_dir, target_filename))
            print(f"  {file_path.name}")
            print(f"    → docs/{target_dir}/{target_filename}")
    
    if skipped_forbidden:
        print(f"\n⚠ Skipped {len(skipped_forbidden)} files (forbidden development directories):")
        for filename, target_dir in skipped_forbidden:
            print(f"  - {filename} (would move to {target_dir})")
        print("\nThese files remain in inbox for manual review.")
    
    if not moves:
        print("\nNo files to move.")
        return
    
    print(f"\n{'='*60}")
    print(f"About to move {len(moves)} files")
    print("="*60)
    
    # Perform moves
    print("\nMoving files and updating metadata...\n")
    moved_count = 0
    
    for old_path, new_path, target_dir, target_filename in moves:
        try:
            # Move file
            old_path.rename(new_path)
            print(f"✓ Moved: {old_path.name} -> docs/{target_dir}/{target_filename}")
            
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
                moved_count += 1
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
            print(f"✗ Error moving {old_path.name}: {e}\n")
    
    print(f"Done! Moved {moved_count} files.")

if __name__ == "__main__":
    main()

