## Test Description

This test verifies safe-profile helper metadata handling. It checks that:
1. A helper with safe metadata can return a typed pointer into a registered region.
2. Safe-profile loads and stores can use that returned pointer.
3. A helper registered only through the legacy API is rejected before dispatch in safe mode.
