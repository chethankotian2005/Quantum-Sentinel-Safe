"""
Live TLS Scan — on-demand website scanning.
DRD Section 7.1 / FR-4

Opens TCP socket to host:443, wraps with ssl.SSLContext,
performs handshake, extracts DER cert, feeds into cert_scanner.
"""
