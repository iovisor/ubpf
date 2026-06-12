## Test Description

This test verifies the safe-profile stack provenance rules. It checks that:
1. A spilled pointer tag is restored by a full-width stack reload.
2. Partial writes invalidate spilled provenance metadata.
3. Caller-saved argument registers are reclassified after a local function returns.
