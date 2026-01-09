#!/usr/bin/env python3
"""
Batch process all files in docs/00_inbox/ according to os_meta/ definitions.
Runs all metadata operations, title extraction, and organization in one go.

This script performs:
1. Metadata creation/update for all inbox files
2. Title extraction from filenames
3. File organization (move to appropriate directories)
4. Final metadata validation

Designed to run at the end of the day or on-demand.
"""
import os
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple

ROOT = Path(__file__).parent.parent
INBOX_DIR = ROOT / "docs" / "00_inbox"
OSMETA_SCRIPT = ROOT / "tools" / "osmeta.py"
ORGANIZE_SCRIPT = ROOT / "tools" / "organize_inbox.py"

def process_metadata(file_path: Path) -> Tuple[bool, str]:
    """Create/update metadata for a file"""
    rel_path = file_path.relative_to(ROOT)
    
    try:
        # Use update (works for both new and existing files)
        result = subprocess.run(
            [sys.executable, str(OSMETA_SCRIPT), "update", str(rel_path)],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
            timeout=10
        )
        
        if result.returncode == 0:
            # Run check to ensure validation
            check_result = subprocess.run(
                [sys.executable, str(OSMETA_SCRIPT), "check", str(rel_path)],
                capture_output=True,
                text=True,
                cwd=str(ROOT),
                timeout=10
            )
            if check_result.returncode == 0:
                return (True, f"✓ {rel_path}")
            else:
                return (False, f"⚠ {rel_path} (check failed: {check_result.stderr.strip()})")
        else:
            return (False, f"✗ {rel_path}: {result.stderr.strip()}")
    except subprocess.TimeoutExpired:
        return (False, f"✗ {rel_path}: Timeout")
    except Exception as e:
        return (False, f"✗ {rel_path}: {str(e)}")

def get_inbox_files() -> List[Path]:
    """Get all files in inbox directory"""
    if not INBOX_DIR.exists():
        return []
    
    files = []
    for file_path in sorted(INBOX_DIR.iterdir()):
        if file_path.is_file() and not file_path.name.endswith(".meta.yaml"):
            files.append(file_path)
    
    return files

def main():
    """Main batch processing function"""
    print("=" * 70)
    print("OS Meta Batch Processing for Inbox Files")
    print("=" * 70)
    print()
    
    # Step 1: Get all inbox files
    files = get_inbox_files()
    if not files:
        print("No files found in inbox. Nothing to process.")
        return
    
    print(f"Step 1: Found {len(files)} files in inbox")
    print()
    
    # Step 2: Process metadata for all files
    print("Step 2: Processing metadata (create/update + title extraction)...")
    print("-" * 70)
    
    success_count = 0
    error_count = 0
    errors = []
    
    for i, file_path in enumerate(files, 1):
        success, message = process_metadata(file_path)
        print(f"[{i}/{len(files)}] {message}")
        
        if success:
            success_count += 1
        else:
            error_count += 1
            errors.append(message)
    
    print()
    print(f"Metadata processing: {success_count} succeeded, {error_count} failed")
    
    if errors:
        print("\nErrors during metadata processing:")
        for error in errors:
            print(f"  {error}")
    
    print()
    print("=" * 70)
    
    # Step 3: Organize files (move to appropriate directories)
    print("Step 3: Organizing files (moving to appropriate directories)...")
    print("-" * 70)
    
    try:
        result = subprocess.run(
            [sys.executable, str(ORGANIZE_SCRIPT)],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=300  # 5 minutes timeout
        )
        
        if result.returncode == 0:
            print(result.stdout)
            print("✓ File organization completed")
        else:
            print(f"⚠ File organization completed with warnings")
            if result.stderr:
                print(result.stderr)
    except subprocess.TimeoutExpired:
        print("✗ File organization timed out")
    except Exception as e:
        print(f"✗ Error during file organization: {e}")
    
    print()
    print("=" * 70)
    print("Batch processing complete!")
    print("=" * 70)
    
    # Summary
    remaining_files = get_inbox_files()
    if remaining_files:
        print(f"\nRemaining files in inbox: {len(remaining_files)}")
        print("(These may have been skipped due to conflicts or errors)")
    else:
        print("\n✓ Inbox is now empty - all files have been processed and organized")

if __name__ == "__main__":
    main()

