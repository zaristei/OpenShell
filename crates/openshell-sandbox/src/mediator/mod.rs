// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Mediation layer: Unix domain socket API for cross-boundary operations.
//!
//! This module implements the syscall-style API that mediates all interactions
//! between an agent process and external resources (network, IPC, namespaces).

pub mod audit;
pub mod auth;
pub mod daemon;
pub mod dashboard;
pub mod gid;
pub mod init;
pub mod namespace;
pub mod peercred;
pub mod policy;
pub mod proto;
pub mod registry;
pub mod store;
pub mod syscalls;
pub mod uid;

pub use init::{MediatorConfig, run_mediator};
