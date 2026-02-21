# Conditional Policy Caching Removal

## Summary
Removed all caching from conditional policy evaluation to fix correctness bug.

## The Problem
Cached policy results could become stale as runtime state changes:
- Helper functions called after first evaluation
- Map accesses added after first check  
- Symbolic memory values becoming concrete

## Changes Made
1. ExecutionState.h - Removed evaluationCache and cache methods
2. ExecutionState.cpp - Removed cache method implementations
3. CONDITIONAL_POLICY_SPEC.md - Updated documentation

## Result
Policies are now re-evaluated on each check, ensuring correctness.
Performance impact is acceptable with short-circuit evaluation.

## Files Modified
- klee/lib/Core/ExecutionState.h
- klee/lib/Core/ExecutionState.cpp
- examples/fw/CONDITIONAL_POLICY_SPEC.md
