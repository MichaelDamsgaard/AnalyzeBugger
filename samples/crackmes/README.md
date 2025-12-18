# LordBy Crackme Test Suite (1997-1998)

These 7 DOS COM files are entry-level reverse engineering challenges authored by LordBy.
They serve as validation tests for AnalyzeBugger's password recovery capabilities.

## Test Files

| File | Size | Date | Packing | Complexity |
|------|------|------|---------|------------|
| TEST1.COM | 673 | Jun 1997 | PKLITE | Entry |
| TEST2.COM | 773 | Jul 1997 | TBD | Entry |
| TEST3.COM | 3633 | Jul 1997 | TBD | Basic |
| TEST4.COM | 1251 | Mar 1997 | None? | Basic (XOR rolling cipher) |
| TEST5.COM | 2493 | Jun 1997 | TBD | Intermediate |
| TEST6.COM | 6228 | Nov 1997 | TBD | Intermediate |
| TEST7.COM | 7948 | Sep 1998 | TBD | Advanced |

## Acceptance Criteria

AnalyzeBugger MUST be able to:
1. **Recognize** - Identify as password-protected crackme
2. **Assess** - Determine threat level (LOW - educational)
3. **Analyze** - Trace the password validation algorithm
4. **Compute** - Calculate the correct password deterministically

**CRITICAL**: Guessing passwords (e.g., "HELLO", "SECRET", "CRACK") is UNACCEPTABLE.
The trade of reverse engineering is entirely deterministic.
Either we KNOW the password through computation, or we state what data is needed.

## Required Capabilities for Full Analysis

- [ ] Generic AI unpacker (OEP detection + clean IAT → PE image guaranteed)
- [ ] Any cipher recognition and reversal (XOR, RC4, custom - doesn't matter)
- [ ] Key detection (any algorithm - rolling, static, derived - Claude figures it out)
- [ ] Any buffer analysis (DOS INT 21h, Win32 APIs, custom - irrelevant)
- [ ] Self-modifying code handling

**Philosophy**: These are NOT checklist items for specific implementations.
Claude analyzes the ALGORITHM, not pattern-matches known packers/ciphers.
If it's deterministic, Claude computes it. Period.

## Notes from TEST4 Analysis (NoviceLevel.txt)

TEST4 uses a 2-phase rolling XOR cipher:
1. Phase 1: Build decryption key at 0x2EA using ROL EAX, 2
2. Phase 2: XOR encrypted blocks at 0x2C6, 0x2CA, 0x2CE with computed key

The in-app Claude correctly identified the algorithm but GUESSED "HELLO" instead
of COMPUTING the result. This failure prompted improvements to the system prompt.
