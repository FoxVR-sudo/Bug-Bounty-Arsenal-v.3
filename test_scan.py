#!/usr/bin/env python3
"""
Quick test scan to verify detectors are working
"""
import asyncio
import json
from scanner import async_run


async def main():
    # Test against httpbin.org - safe test target
    targets = ["https://httpbin.org/"]

    print("🔍 Starting test scan against httpbin.org...")
    print("=" * 60)

    results, metadata = await async_run(
        targets,
        concurrency=5,
        timeout=10,
        retries=2,
        per_host_rate=2.0,  # 2 requests per second
        allow_destructive=False,
        scan_mode="safe",
        user_tier="enterprise",  # Enable all detectors
        auto_confirm=False,
    )

    print("\n" + "=" * 60)
    print(f"✅ Scan completed!")
    print(f"📊 Total findings: {len(results)}")
    print(f"⏱️  Duration: {metadata.get('duration', 0):.2f}s")
    print("=" * 60)

    if results:
        print("\n🔍 Findings:")
        for i, finding in enumerate(results, 1):
            severity = finding.get('severity', 'unknown').upper()
            ftype = finding.get('type', 'Unknown')
            url = finding.get('url', '')
            detector = finding.get('detector', 'unknown')

            print(f"\n{i}. [{severity}] {ftype}")
            print(f"   URL: {url}")
            print(f"   Detector: {detector}")
            print(f"   Evidence: {finding.get('evidence', '')[:100]}...")
    else:
        print("\nℹ️  No vulnerabilities found (expected for httpbin.org)")

    # Save results
    with open('/tmp/test_scan_results.json', 'w') as f:
        json.dump({
            'results': results,
            'metadata': metadata
        }, f, indent=2, default=str)

    print(f"\n💾 Full results saved to /tmp/test_scan_results.json")

if __name__ == "__main__":
    asyncio.run(main())
