# Contributing

Thank you for contributing to NetSentinel11.

## Local setup

1. Build with CMake (MSVC 2022 / Windows 11)
2. Keep changes minimal and module-scoped.
3. Preserve public APIs unless absolutely necessary.
4. Keep staged work backward-compatible with existing docs and tests.

## Code style

- C code: C17
- Application and module code: C++20
- Prefer small, testable interfaces.
- Prefer clear logging and safe failure paths.

## Safety and review rules

- No stealth or disruptive network behavior.
- Default actions should stay local and safe.
- Any optional dependency must be discovered and handled with clear warnings when unavailable.

## Testing

- Use CTest targets defined in this repo.
- Document command and expected output for every prompt/task handoff.

