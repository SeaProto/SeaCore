# SeaCore Testing Matrix

This matrix is designed to reduce both false positives and false negatives:

- Uses only local loopback services (`127.0.0.1`) for deterministic behavior.
- Avoids public DNS/HTTP dependencies.
- Uses explicit readiness checks, strict assertions, and bounded timeouts.
- Captures process logs and prints tails on failure.

## Coverage

| Area | Implementation | Command |
| --- | --- | --- |
| Protocol fuzz regression | deterministic byte-stream fuzz for `Header::unmarshal` | `cargo test -p seacore-protocol protocol_fuzz_unmarshal_never_panics` |
| Protocol roundtrip matrix | deterministic random header roundtrip checks | `cargo test -p seacore-protocol deterministic_protocol_roundtrip_matrix` |
| Long-run stability | repeated TCP and UDP roundtrip stress | `python Test/test_matrix.py --tcp-iterations 40 --udp-iterations 80` |
| Reconnect resilience | stop/start server while keeping client alive, verify recovery + metric growth | `python Test/test_matrix.py --skip-long --skip-nat` |
| NAT rebinding | UDP source port change across same SOCKS5 UDP associate control channel | `python Test/test_matrix.py --skip-long --skip-reconnect` |
| Cross-platform e2e | same script works on Windows/Linux/macOS | `Test/test_e2e.ps1` or `Test/test_e2e.sh` |

## Primary Commands

```bash
cargo test -p seacore-protocol
python Test/test_matrix.py
```

Windows wrapper:

```powershell
pwsh Test/test_e2e.ps1
```

Linux/macOS wrapper:

```bash
bash Test/test_e2e.sh
```

## Notes

- The matrix runner expects a release binary at `target/release/seacore` (or `.exe` on Windows).
- Wrappers build the release binary before running tests.
- `test_matrix.py` supports quick smoke mode through flags:
  - `--skip-long`
  - `--skip-nat`
  - `--skip-reconnect`
