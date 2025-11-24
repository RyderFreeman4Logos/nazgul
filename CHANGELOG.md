5d643de3f6cab17ed6660b6c468a883145882b2d
### Plan: BLSAG Optimization

Created `TODO.md` and `TODO.zh.md` to outline the roadmap for optimizing the bLSAG signature scheme.
The optimization focuses on two key areas:
1.  **Memory & Readability in `sign`**: Reducing heap allocations by removing the `cs` vector (saving O(N) space) and simplifying the challenge generation loop using iterators.
2.  **Performance in `Ring::new`**: Pre-calculating compressed points to avoid repeated expensive curve operations during sorting (O(N log N) -> O(N)).

This planning step ensures a clear path forward before touching the core cryptographic code.
