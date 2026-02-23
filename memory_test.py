#!/usr/bin/env python3
"""Script to measure memory usage of URL objects.

Usage:
    python memory_test.py [COUNT] [--dict]
    
Arguments:
    COUNT       Number of objects to create (default: 10000)
    --dict      Use dict form (.toDict()) instead of URL objects
    
Examples:
    python memory_test.py              # 10k URL objects
    python memory_test.py 100000       # 100k URL objects
    python memory_test.py 50000 --dict # 50k dicts
"""

import sys
import gc
import argparse
import tracemalloc

from secator.output_types.url import Url


def create_sample_url(i: int) -> Url:
    """Create a sample URL object with realistic data."""
    return Url(
        url=f"https://example{i}.com/path/to/resource?param=value{i}",
        host=f"example{i}.com",
        status_code=200,
        title=f"Example Page {i}",
        webserver="nginx/1.18.0",
        tech=["PHP", "WordPress", "jQuery"],
        content_type="text/html",
        content_length=12345,
        method="GET",
        words=500,
        lines=50,
        response_headers={
            "Server": "nginx/1.18.0",
            "Content-Type": "text/html; charset=utf-8",
            "X-Frame-Options": "SAMEORIGIN",
        },
        request_headers={
            "User-Agent": "Mozilla/5.0",
            "Accept": "text/html",
        },
    )


def get_deep_size(obj, seen=None):
    """Recursively calculate object size including nested objects."""
    if seen is None:
        seen = set()
    
    obj_id = id(obj)
    if obj_id in seen:
        return 0
    seen.add(obj_id)
    
    size = sys.getsizeof(obj)
    
    if isinstance(obj, dict):
        size += sum(get_deep_size(k, seen) + get_deep_size(v, seen) for k, v in obj.items())
    elif isinstance(obj, (list, tuple, set, frozenset)):
        size += sum(get_deep_size(item, seen) for item in obj)
    elif hasattr(obj, '__dict__'):
        size += get_deep_size(obj.__dict__, seen)
    elif hasattr(obj, '__slots__'):
        size += sum(get_deep_size(getattr(obj, slot), seen) for slot in obj.__slots__ if hasattr(obj, slot))
    
    return size


def main():
    parser = argparse.ArgumentParser(description="Measure memory usage of URL objects")
    parser.add_argument("count", type=int, nargs="?", default=10000, help="Number of objects to create (default: 10000)")
    parser.add_argument("--dict", action="store_true", dest="use_dict", help="Use dict form (.toDict()) instead of URL objects")
    args = parser.parse_args()
    
    count = args.count
    use_dict = args.use_dict
    form_name = "DICT" if use_dict else "URL OBJECT"
    
    gc.collect()
    
    print("=" * 50)
    print(f"{form_name} MEMORY TEST")
    print("=" * 50)
    
    tracemalloc.start()
    
    print(f"Creating {count:,} URL objects...")
    urls = [create_sample_url(i) for i in range(count)]
    
    if use_dict:
        print(f"Converting to dicts...")
        data = [url.toDict() for url in urls]
        del urls
        gc.collect()
    else:
        data = urls
    
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    print(f"\nResults (tracemalloc):")
    print(f"  Total {form_name.lower()}s: {len(data):,}")
    print(f"  Current memory: {current:,} bytes ({current / 1024 / 1024:.2f} MB)")
    print(f"  Peak memory:    {peak:,} bytes ({peak / 1024 / 1024:.2f} MB)")
    print(f"  Avg per {form_name.lower()}: {current / len(data):.2f} bytes")
    
    # Deep size calculation for a single object
    single_url = create_sample_url(0)
    if use_dict:
        single = single_url.toDict()
    else:
        single = single_url
    single_size = get_deep_size(single)
    print(f"\nSingle {form_name.lower()} (deep size): {single_size:,} bytes")
    print(f"Estimated {count:,} {form_name.lower()}s: {single_size * count:,} bytes ({single_size * count / 1024 / 1024:.2f} MB)")
    
    # Minimal URL
    minimal_url = Url(url="https://example.com")
    if use_dict:
        minimal = minimal_url.toDict()
    else:
        minimal = minimal_url
    minimal_size = get_deep_size(minimal)
    print(f"\nMinimal {form_name.lower()} (deep size): {minimal_size:,} bytes")
    print(f"Estimated {count:,} minimal: {minimal_size * count:,} bytes ({minimal_size * count / 1024 / 1024:.2f} MB)")


if __name__ == "__main__":
    main()
