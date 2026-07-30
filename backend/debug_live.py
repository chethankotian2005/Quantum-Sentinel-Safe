from detection.live_scanner import scan_live_host

print("untrusted-root:")
for f in scan_live_host("untrusted-root.badssl.com"):
    print(f.algorithm)

print("mozilla:")
for f in scan_live_host("mozilla.org"):
    print(f.algorithm)
