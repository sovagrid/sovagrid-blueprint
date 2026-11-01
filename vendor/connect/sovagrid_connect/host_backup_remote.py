# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Read-only proof of the exact installed host backup helper and server package."""

from .release_feed_remote import SOURCE_PROOF


SCRIPT = SOURCE_PROOF + r'''
try:
    need(len(sys.argv) == 2 or
         (len(sys.argv) == 3 and sys.argv[2] == 'portable'), 'ARGS')
    expected = sys.argv[1]
    hashes = source(expected)
    need({'sovagrid-blueprint/deploy/host_backup.py',
          'sovagrid-blueprint/deploy/host_backup_orchestrator.py'} <= set(hashes),
         'SOURCE_MANIFEST')
    result = {'protocol': 1, 'manifest_sha256': expected,
              'host_backup_verified': True}
    if len(sys.argv) == 3:
        orchestrator = 'sovagrid-blueprint/deploy/host_backup_orchestrator.py'
        image_export = 'sovagrid-blueprint/deploy/host_image_export.py'
        need(image_export in hashes, 'PORTABLE_UNAVAILABLE')
        for relative, required in ((orchestrator, (b'start-portable',
                                                    b'portable-status',
                                                    b'sovagrid-portable-host-receipt-v1')),
                                   (image_export, (b'verify-portable',
                                                   b'sovagrid-portable-host-receipt-v1'))):
            raw = (ROOT / relative).read_bytes()
            need(hashlib.sha256(raw).hexdigest() == hashes[relative] and
                 all(token in raw for token in required), 'PORTABLE_UNAVAILABLE')
        result['portable_verified'] = True
    print(json.dumps(result,
                     sort_keys=True, separators=(',', ':')))
except (Refused, OSError, ValueError, TypeError, UnicodeError) as exc:
    code = str(exc) if isinstance(exc, Refused) else 'UNVERIFIED'
    print('SG_HOST_BACKUP_SOURCE_REFUSE:' + code)
    raise SystemExit(40)
'''
