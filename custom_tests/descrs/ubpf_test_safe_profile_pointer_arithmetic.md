## Test Description

This test verifies the safe-profile pointer arithmetic rules. It checks that:
1. `pointer + pointer` fails.
2. `scalar - pointer` fails.
3. `pointer - pointer` within the same region returns a scalar difference.
4. `pointer - pointer` across different regions fails.
