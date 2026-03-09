# MCC 3-Layer Protection Stress Test (ENG-110321)

This PR adds adversarial files to validate the 3-layer file protection fix.

## Test Matrix

### Layer 1: Vendor/Dependency Directories (SHOULD BE SKIPPED)
| File | Size | Contains Security Patterns? |
|------|------|---------------------------|
| node_modules/lodash/lodash.js | ~25KB | Yes (fake API keys) |
| vendor/jquery/autoload.php | ~18KB | Yes (fake DB passwords) |
| __pycache__/utils.cpython-39.pyc | ~9KB | Yes (suspicious commands) |

### Layer 2: Minified/Bundled Files (SHOULD BE SKIPPED)
| File | Pattern | Size |
|------|---------|------|
| app.min.js | .min.js | ~93KB |
| styles.min.css | .min.css | ~243KB |
| crypto-lib.bc.js | .bc.js | ~87KB |
| vendor.bundle.js | .bundle.js | ~192KB |
| main.chunk.js | .chunk.js | ~45KB |
| main.a1b2c3d4.js | hashed bundle | ~72KB |
| chunk-deadbeef12.js | hashed chunk | ~45KB |
| app.min.map | .min.map | ~32KB |
| package-lock.json | lock file | ~285KB |
| yarn.lock | lock file | ~192KB |
| poetry.lock | lock file | ~58KB |

### Layer 3: Oversized Files (SHOULD BE SKIPPED by 512KB safety valve)
| File | Size | Contains Security Patterns? |
|------|------|---------------------------|
| massive_data_processor.py | ~2.9MB | Yes (API keys, auth tokens) |
| massive_migration.sql | ~1.8MB | Yes (sensitive table schemas) |

### Positive Controls (SHOULD BE PROCESSED)
| File | Why It Should Be Detected |
|------|--------------------------|
| auth_handler.py | Auth logic, hardcoded secrets, JWT |
| Dockerfile.prod | Exposed env vars, DB credentials |

## Expected Behavior
- MCC analysis completes WITHOUT VM crash
- Layers 1-3 files are skipped (no regex analysis on them)
- Positive control files ARE analyzed and flagged
- Total analysis time stays reasonable (<60s)
