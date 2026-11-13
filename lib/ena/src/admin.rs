// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The admin and event queue entries. The numbers are definitions of
//! `ena_admin_defs.h` and `ena_common_defs.h` (FreeBSD
//! `sys/contrib/ena-com/ena_defs/`, DPDK `drivers/net/ena/base/ena_defs/`,
//! BSD-3-Clause, see `NOTICE`): the opcodes, the statuses, the feature
//! numbers, the event groups, and the byte offsets of the fields of the
//! structures the header lays out (offsets are the sums of the header's field
//! sizes, checked by the tests against the sizes the header gives:
//! 64-byte entries). The names are the header's without the `ENA_ADMIN_`
//! prefix.

/// An entry of the admin queue, of its completion queue and of the event
/// queue: `struct ena_admin_aq_entry`, `ena_admin_acq_entry` and
/// `ena_admin_aenq_entry` are 64 bytes each.
pub const ENTRY: usize = 64;

// enum ena_admin_aq_opcode.
pub const CREATE_SQ: u8 = 1;
pub const DESTROY_SQ: u8 = 2;
pub const CREATE_CQ: u8 = 3;
pub const DESTROY_CQ: u8 = 4;
pub const GET_FEATURE: u8 = 8;
pub const SET_FEATURE: u8 = 9;
pub const GET_STATS: u8 = 11;

// enum ena_admin_aq_completion_status.
pub const SUCCESS: u8 = 0;
pub const RESOURCE_ALLOCATION_FAILURE: u8 = 1;
pub const BAD_OPCODE: u8 = 2;
pub const UNSUPPORTED_OPCODE: u8 = 3;
pub const MALFORMED_REQUEST: u8 = 4;
pub const ILLEGAL_PARAMETER: u8 = 5;
pub const UNKNOWN_ERROR: u8 = 6;
pub const RESOURCE_BUSY: u8 = 7;

// enum ena_admin_aq_feature_id.
pub const DEVICE_ATTRIBUTES: u8 = 1;
pub const MAX_QUEUES_NUM: u8 = 2;
pub const HW_HINTS: u8 = 3;
pub const LLQ: u8 = 4;
pub const MAX_QUEUES_EXT: u8 = 7;
pub const RSS_HASH_FUNCTION: u8 = 10;
pub const STATELESS_OFFLOAD_CONFIG: u8 = 11;
pub const MTU: u8 = 14;
pub const AENQ_CONFIG: u8 = 26;
pub const LINK_CONFIG: u8 = 27;

// enum ena_admin_aq_caps_id: the bits of `capabilities` of the device
// attributes.
pub const CAP_ENI_STATS: u32 = 0;
pub const CAP_CUSTOMER_METRICS: u32 = 2;
pub const CAP_EXTENDED_RESET_REASONS: u32 = 3;

// enum ena_admin_get_stats_type and enum ena_admin_get_stats_scope.
pub const STATS_TYPE_BASIC: u8 = 0;
pub const STATS_TYPE_ENI: u8 = 2;
pub const STATS_SCOPE_ETH_TRAFFIC: u8 = 1;

// enum ena_admin_aenq_group.
pub const AENQ_LINK_CHANGE: u16 = 0;
pub const AENQ_FATAL_ERROR: u16 = 1;
pub const AENQ_WARNING: u16 = 2;
pub const AENQ_NOTIFICATION: u16 = 3;
pub const AENQ_KEEP_ALIVE: u16 = 4;
pub const AENQ_REFRESH_CAPABILITIES: u16 = 5;
pub const AENQ_CONF_NOTIFICATIONS: u16 = 6;
pub const AENQ_DEVICE_REQUEST_RESET: u16 = 7;

// enum ena_admin_aenq_notification_syndrome.
pub const AENQ_UPDATE_HINTS: u16 = 2;

/// `ena_admin_aq_common_desc`: `command_id` (11:0) at 0, `opcode` at 2, `flags`
/// at 3 with the phase in bit 0.
pub const AQ_COMMAND_ID_MASK: u16 = 0x0fff;
pub const AQ_OPCODE: usize = 2;
pub const AQ_FLAGS: usize = 3;
pub const AQ_FLAG_PHASE: u8 = 1;

/// `ena_admin_get_set_feature_common_desc` follows the common descriptor
/// (4 bytes) and the control buffer info (`length` and a 48-bit address, 12
/// bytes) of `ena_admin_get_feat_cmd` and `ena_admin_set_feat_cmd`: `flags`
/// (`select`: 0x1 current value) at 16, `feature_id` at 17,
/// `feature_version` at 18; the feature's own fields from 20.
pub const FEAT_FLAGS: usize = 16;
pub const FEAT_ID: usize = 17;
pub const FEAT_VERSION: usize = 18;
pub const FEAT_DATA: usize = 20;
/// `select` of `flags`: 0x1 asks for the current value (the commands here leave 0).
pub const FEAT_SELECT_CURRENT: u8 = 1;

/// `ena_admin_aq_get_stats_cmd`: `type` at 16, `scope` at 17, `queue_idx` at
/// 20, `device_id` at 22 (0xFFFF means this device).
pub const STATS_TYPE: usize = 16;
pub const STATS_SCOPE: usize = 17;
pub const STATS_QUEUE: usize = 20;
pub const STATS_DEVICE: usize = 22;
pub const DEVICE_ME: u16 = 0xFFFF;

/// `ena_admin_acq_common_desc`: `command` at 0 (11:0), `status` at 2,
/// `flags` at 3 with the phase in bit 0, `extended_status` at 4,
/// `sq_head_indx` at 6; the response's own fields from 8.
pub const ACQ_COMMAND: usize = 0;
pub const ACQ_STATUS: usize = 2;
pub const ACQ_FLAGS: usize = 3;
pub const ACQ_EXTENDED_STATUS: usize = 4;
pub const ACQ_DATA: usize = 8;
pub const ACQ_FLAG_PHASE: u8 = 1;

/// `ena_admin_device_attr_feature_desc`, from `ACQ_DATA`: `impl_id` 0,
/// `device_version` 4, `supported_features` 8, `capabilities` 12,
/// `phys_addr_width` 16, `virt_addr_width` 20, `mac_addr` 24 (6 bytes),
/// `max_mtu` 32.
pub const ATTR_IMPL_ID: usize = 0;
pub const ATTR_VERSION: usize = 4;
pub const ATTR_SUPPORTED: usize = 8;
pub const ATTR_CAPABILITIES: usize = 12;
pub const ATTR_PHYS_WIDTH: usize = 16;
pub const ATTR_VIRT_WIDTH: usize = 20;
pub const ATTR_MAC: usize = 24;
pub const ATTR_MAX_MTU: usize = 32;

/// `ena_admin_queue_ext_feature_desc`, from `ACQ_DATA`: `version` at 0 and
/// then `ena_admin_queue_ext_feature_fields` from 4: `max_tx_sq_num` 4,
/// `max_tx_cq_num` 8, `max_rx_sq_num` 12, `max_rx_cq_num` 16,
/// `max_tx_sq_depth` 20, `max_tx_cq_depth` 24, `max_rx_sq_depth` 28,
/// `max_rx_cq_depth` 32, `max_tx_header_size` 36, `max_per_packet_tx_descs`
/// (16 bits) 40, `max_per_packet_rx_descs` (16 bits) 42.
pub const QEXT_TX_SQ_NUM: usize = 4;
pub const QEXT_TX_CQ_NUM: usize = 8;
pub const QEXT_RX_SQ_NUM: usize = 12;
pub const QEXT_RX_CQ_NUM: usize = 16;
pub const QEXT_TX_SQ_DEPTH: usize = 20;
pub const QEXT_TX_CQ_DEPTH: usize = 24;
pub const QEXT_RX_SQ_DEPTH: usize = 28;
pub const QEXT_RX_CQ_DEPTH: usize = 32;
pub const QEXT_TX_HEADER: usize = 36;

/// `ena_admin_queue_feature_desc` (the legacy `MAX_QUEUES_NUM`), from
/// `ACQ_DATA`: `max_sq_num` 0, `max_sq_depth` 4, `max_cq_num` 8,
/// `max_cq_depth` 12.
pub const QUEUE_SQ_NUM: usize = 0;
pub const QUEUE_SQ_DEPTH: usize = 4;
pub const QUEUE_CQ_NUM: usize = 8;
pub const QUEUE_CQ_DEPTH: usize = 12;

/// `ena_admin_ena_hw_hints`, from `ACQ_DATA`, 16 bits each: `mmio_read_timeout`
/// 0 (ms), `driver_watchdog_timeout` 2 (ms), `missing_tx_completion_timeout`
/// 4 (ms), `missed_tx_completion_count_threshold_to_reset` 6,
/// `admin_completion_tx_timeout` 8 (ms), `netdev_wd_timeout` 10 (ms),
/// `max_tx_sgl_size` 12, `max_rx_sgl_size` 14. `HINT_NO_TIMEOUT`
/// (`ENA_HW_HINTS_NO_TIMEOUT` of ena_com.h) says the device wants no timeout.
pub const HINT_MMIO_READ: usize = 0;
pub const HINT_WATCHDOG: usize = 2;
pub const HINT_MISSING_TX: usize = 4;
pub const HINT_MISSING_TX_COUNT: usize = 6;
pub const HINT_ADMIN: usize = 8;
pub const HINT_NO_TIMEOUT: u16 = 0xFFFF;

/// `ena_admin_feature_offload_desc`, from `ACQ_DATA`: `tx` 0, `rx_supported`
/// 4, `rx_enabled` 8.
pub const OFFLOAD_TX: usize = 0;
pub const OFFLOAD_RX_SUPPORTED: usize = 4;
pub const OFFLOAD_RX_ENABLED: usize = 8;

/// `ena_admin_feature_aenq_desc`, from `ACQ_DATA` and from `FEAT_DATA` of a
/// set: `supported_groups` 0, `enabled_groups` 4 (the set command writes the
/// pair at `FEAT_DATA`, the device reads `enabled_groups` from `FEAT_DATA +
/// 4`).
pub const AENQ_SUPPORTED: usize = 0;
pub const AENQ_ENABLED: usize = 4;

/// `ena_admin_feature_llq_desc`, from `ACQ_DATA`: `max_llq_num` 0,
/// `max_llq_depth` 4, `header_location_ctrl_supported` (16 bits) 8.
pub const LLQ_MAX_NUM: usize = 0;
pub const LLQ_MAX_DEPTH: usize = 4;
pub const LLQ_HEADER_LOCATION: usize = 8;

/// `ena_admin_get_feature_link_desc`, from `ACQ_DATA`: `speed` (Mb/s) 0,
/// `supported` 4, `flags` 8.
pub const LINK_SPEED: usize = 0;

/// The MTU the set command writes at `FEAT_DATA` (`ena_admin_set_feature_mtu_desc`,
/// excluding L2).
pub const MTU_VALUE: usize = 0;

/// `ena_admin_eni_stats`, from `ACQ_DATA`, five 64-bit counters:
/// `bw_in_allowance_exceeded` 0, `bw_out_allowance_exceeded` 8,
/// `pps_allowance_exceeded` 16, `conntrack_allowance_exceeded` 24,
/// `linklocal_allowance_exceeded` 32.
pub const ENI_COUNTERS: usize = 5;

/// `ena_admin_basic_stats`, from `ACQ_DATA`, 64-bit values in a low and a high
/// word: `tx_bytes` 0, `tx_pkts` 8, `rx_bytes` 16, `rx_pkts` 24, `rx_drops`
/// 32, `tx_drops` 40, `rx_overruns` 48.
pub const BASIC_TX_BYTES: usize = 0;
pub const BASIC_TX_PKTS: usize = 8;
pub const BASIC_RX_BYTES: usize = 16;
pub const BASIC_RX_PKTS: usize = 24;
pub const BASIC_RX_DROPS: usize = 32;
pub const BASIC_TX_DROPS: usize = 40;

/// `ena_admin_aenq_common_desc`: `group` (16 bits) at 0, `syndrome` (16
/// bits) at 2, `flags` at 4 with the phase in bit 0, `timestamp_low` at 8,
/// `timestamp_high` at 12; the event's own fields from 16.
pub const AENQ_GROUP: usize = 0;
pub const AENQ_SYNDROME: usize = 2;
pub const AENQ_FLAGS: usize = 4;
pub const AENQ_FLAG_PHASE: u8 = 1;
pub const AENQ_DATA: usize = 16;

/// `ena_admin_aenq_link_change_desc`: `flags` at `AENQ_DATA`, bit 0 the
/// link status.
pub const LINK_STATUS_MASK: u32 = 1;

/// `ena_admin_aenq_keep_alive_desc`, from `AENQ_DATA`: `rx_drops` (low,
/// high) 0, `tx_drops` 8, `rx_overruns` 16.
pub const KA_RX_DROPS: usize = 0;
pub const KA_TX_DROPS: usize = 8;
pub const KA_RX_OVERRUNS: usize = 16;

/// `ena_admin_ena_mmio_req_read_less_resp`: `req_id` (16 bits) at 0,
/// `reg_off` (16 bits) at 2, `reg_val` at 4; 8 bytes.
pub const READLESS_REQ_ID: usize = 0;
pub const READLESS_REG_OFF: usize = 2;
pub const READLESS_REG_VAL: usize = 4;
pub const READLESS_LEN: usize = 8;

/// Depth of the admin queue and of its completion queue
/// (`ENA_ADMIN_QUEUE_DEPTH` of ena_com.c), and of the event queue
/// (`ENA_ASYNC_QUEUE_DEPTH`).
pub const ADMIN_DEPTH: u16 = 32;
pub const EVENT_DEPTH: u16 = 16;
/// `ENA_MAX_PHYS_ADDR_SIZE_BITS` of ena_com.h.
pub const MAX_PHYS_ADDR_BITS: u32 = 48;
/// `ADMIN_CMD_TIMEOUT_US` of ena_com.c: the admin command timeout a device
/// that gives none (`CAPS.ADMIN_CMD_TO` 0) gets, in microseconds.
pub const ADMIN_CMD_TIMEOUT_US: u64 = 3_000_000;
/// `ENA_DEFAULT_KEEP_ALIVE_TO` of the FreeBSD driver's ena.h: 6 seconds.
pub const KEEP_ALIVE_TIMEOUT_MS: u64 = 6_000;
