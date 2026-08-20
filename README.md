# Modular Security Framework

## Project Overview

This project was born out of a desire to understand the architecture of professional security frameworks like Metasploit. It has quickly evolved to be a headless/mcp server for ML model orchestration and security research.

## Technical Architecture

The framework utilizes a hybrid approach to balance performance and flexibility:

- **C++ Core:** Used for low-level systems interaction and high-performance execution.

- **Python Wrapper/Orchestration:** Used for rapid development of modules, automation, and a more flexible user interface.

- **Memory Service:** Provides persistent, namespaced vector memory for cross-harness recall.

- **MCP Server:** Manages the orchestration of ML models and facilitates communication between different components of the framework.

## Learning Objectives

- **Inter-process Communication:** Understanding how high-level languages (Python) can interface with low-level binaries (C++).
- **Modular Design:** Creating a system where new "capabilities" can be added without rewriting the core engine.
- **Security Tooling:** Analyzing how frameworks structure payloads, listeners, and target profiles.

## Current Status

This is an ongoing research project used for educational purposes in a controlled lab environment.
