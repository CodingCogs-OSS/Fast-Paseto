# Product Overview

fast-paseto is a high-performance PASETO (Platform-Agnostic Security Tokens) library implemented in Rust with Python bindings.

## Purpose
Provide a secure, fast, and easy-to-use API for creating and verifying PASETO tokens in Python applications, leveraging Rust's performance and safety guarantees.

## Key Features
- Generate and verify PASETO local tokens (symmetric encryption)
- Generate and verify PASETO public tokens (asymmetric signing)
- Key generation utilities for both token types
- Standard claims management (iss, sub, aud, exp, nbf, iat, jti)
- Primary focus on v4 tokens (modern, recommended)
- Optional support for v3 (NIST-compliant) and v2 (legacy)

## Target Users
Python developers who need secure token-based authentication without the pitfalls of JWT.
