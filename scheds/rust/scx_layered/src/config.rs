// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
use std::fs;
use std::io::Read;

use anyhow::Result;
use serde::Deserialize;
use serde::Serialize;

use crate::bpf_intf;
use crate::LayerGrowthAlgo;

use scx_utils::Cpumask;

mod cpumask_serde {
    use super::*;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(cpumask: &Option<Cpumask>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match cpumask {
            Some(mask) => serializer.serialize_some(&format!("{:x}", mask)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Cpumask>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: Option<String> = Option::deserialize(deserializer)?;
        match s {
            Some(s) => {
                // Try parsing as hex/special value first
                Cpumask::from_str(&s)
                    .or_else(|_| {
                        // Fall back to CPU list format
                        Cpumask::from_cpulist(&s)
                    })
                    .map(Some)
                    .map_err(serde::de::Error::custom)
            }
            None => Ok(None),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LayerConfig {
    pub specs: Vec<LayerSpec>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LayerSpec {
    pub name: String,
    #[serde(default, with = "cpumask_serde")]
    pub cpuset: Option<Cpumask>,
    pub comment: Option<String>,
    pub template: Option<LayerMatch>,
    pub matches: Vec<Vec<LayerMatch>>,
    pub kind: LayerKind,
}

impl LayerSpec {
    pub fn parse(input: &str) -> Result<Vec<Self>> {
        let config: LayerConfig = if input.starts_with("f:") || input.starts_with("file:") {
            let mut f = fs::OpenOptions::new()
                .read(true)
                .open(input.split_once(':').unwrap().1)?;
            let mut content = String::new();
            f.read_to_string(&mut content)?;
            serde_json::from_str(&content)?
        } else {
            serde_json::from_str(input)?
        };
        Ok(config.specs)
    }

    pub fn nodes(&self) -> &Vec<usize> {
        &self.kind.common().nodes
    }

    pub fn llcs(&self) -> &Vec<usize> {
        &self.kind.common().llcs
    }

    pub fn nodes_mut(&mut self) -> &mut Vec<usize> {
        &mut self.kind.common_mut().nodes
    }

    pub fn llcs_mut(&mut self) -> &mut Vec<usize> {
        &mut self.kind.common_mut().llcs
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum LayerPlacement {
    #[default]
    Standard,
    Sticky,
    Floating,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum LayerMatch {
    CgroupPrefix(String),
    CgroupSuffix(String),
    CgroupContains(String),
    CgroupRegex(String),
    CommPrefix(String),
    CommPrefixExclude(String),
    PcommPrefix(String),
    PcommPrefixExclude(String),
    NiceAbove(i32),
    NiceBelow(i32),
    NiceEquals(i32),
    UIDEquals(u32),
    GIDEquals(u32),
    PIDEquals(u32),
    PPIDEquals(u32),
    TGIDEquals(u32),
    NSPIDEquals(u64, u32),
    NSEquals(u32),
    CmdJoin(String),
    IsGroupLeader(bool),
    IsKthread(bool),
    UsedGpuTid(bool),
    UsedGpuPid(bool),
    AvgRuntime(u64, u64),
    HintEquals(u64),
    SystemCpuUtilBelow(f64),
    DsqInsertBelow(f64),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LayerCommon {
    #[serde(default)]
    pub min_exec_us: u64,
    #[serde(default)]
    pub yield_ignore: f64,
    #[serde(default)]
    pub slice_us: u64,
    #[serde(default)]
    pub fifo: bool,
    #[serde(default)]
    pub preempt: bool,
    #[serde(default)]
    pub preempt_first: bool,
    #[serde(default)]
    pub exclusive: bool,
    #[serde(default)]
    pub allow_node_aligned: bool,
    #[serde(default)]
    pub skip_remote_node: bool,
    #[serde(default)]
    pub prev_over_idle_core: bool,
    #[serde(default)]
    pub weight: u32,
    #[serde(default)]
    pub disallow_open_after_us: Option<u64>,
    #[serde(default)]
    pub disallow_preempt_after_us: Option<u64>,
    #[serde(default)]
    pub xllc_mig_min_us: f64,
    #[serde(default, skip_serializing)]
    pub idle_smt: Option<bool>,
    #[serde(default)]
    pub growth_algo: LayerGrowthAlgo,
    #[serde(default)]
    pub perf: u64,
    #[serde(default)]
    pub idle_resume_us: Option<u32>,
    #[serde(default)]
    pub nodes: Vec<usize>,
    #[serde(default)]
    pub llcs: Vec<usize>,
    #[serde(default)]
    pub placement: LayerPlacement,
    #[serde(default)]
    pub member_expire_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum LayerKind {
    Confined {
        util_range: (f64, f64),
        #[serde(default)]
        cpus_range: Option<(usize, usize)>,

        #[serde(default)]
        cpus_range_frac: Option<(f64, f64)>,

        #[serde(default)]
        membw_gb: Option<f64>,

        #[serde(default)]
        protected: bool,

        #[serde(flatten)]
        common: LayerCommon,
    },
    Grouped {
        util_range: (f64, f64),
        #[serde(default)]
        util_includes_open_cputime: bool,
        #[serde(default)]
        cpus_range: Option<(usize, usize)>,

        #[serde(default)]
        cpus_range_frac: Option<(f64, f64)>,

        #[serde(default)]
        membw_gb: Option<f64>,

        #[serde(default)]
        protected: bool,

        #[serde(flatten)]
        common: LayerCommon,
    },
    Open {
        #[serde(flatten)]
        common: LayerCommon,
    },
}

impl LayerKind {
    pub fn as_bpf_enum(&self) -> i32 {
        match self {
            LayerKind::Confined { .. } => bpf_intf::layer_kind_LAYER_KIND_CONFINED as i32,
            LayerKind::Grouped { .. } => bpf_intf::layer_kind_LAYER_KIND_GROUPED as i32,
            LayerKind::Open { .. } => bpf_intf::layer_kind_LAYER_KIND_OPEN as i32,
        }
    }

    pub fn common(&self) -> &LayerCommon {
        match self {
            LayerKind::Confined { common, .. }
            | LayerKind::Grouped { common, .. }
            | LayerKind::Open { common, .. } => common,
        }
    }

    pub fn common_mut(&mut self) -> &mut LayerCommon {
        match self {
            LayerKind::Confined { common, .. }
            | LayerKind::Grouped { common, .. }
            | LayerKind::Open { common, .. } => common,
        }
    }

    pub fn util_range(&self) -> Option<(f64, f64)> {
        match self {
            LayerKind::Confined { util_range, .. } | LayerKind::Grouped { util_range, .. } => {
                Some(*util_range)
            }
            _ => None,
        }
    }

    pub fn util_includes_open_cputime(&self) -> bool {
        match self {
            LayerKind::Grouped {
                util_includes_open_cputime,
                ..
            } => *util_includes_open_cputime,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpumask_deserialize_hex() {
        let json = r#"{
            "name": "test",
            "cpuset": "0xff",
            "matches": [[]],
            "kind": {
                "Open": {}
            }
        }"#;

        let spec: LayerSpec = serde_json::from_str(json).unwrap();
        assert!(spec.cpuset.is_some());
        let mask = spec.cpuset.as_ref().unwrap();

        // 0xff should have CPUs 0-7 set
        for i in 0..8 {
            assert!(mask.test_cpu(i), "CPU {} should be set", i);
        }
        for i in 8..16 {
            assert!(!mask.test_cpu(i), "CPU {} should not be set", i);
        }
    }

    #[test]
    fn test_cpumask_deserialize_cpulist() {
        let json = r#"{
            "name": "test",
            "cpuset": "0-3,5,7",
            "matches": [[]],
            "kind": {
                "Open": {}
            }
        }"#;

        let spec: LayerSpec = serde_json::from_str(json).unwrap();
        assert!(spec.cpuset.is_some());
        let mask = spec.cpuset.as_ref().unwrap();

        // Should have CPUs 0, 1, 2, 3, 5, 7 set
        assert!(mask.test_cpu(0));
        assert!(mask.test_cpu(1));
        assert!(mask.test_cpu(2));
        assert!(mask.test_cpu(3));
        assert!(!mask.test_cpu(4));
        assert!(mask.test_cpu(5));
        assert!(!mask.test_cpu(6));
        assert!(mask.test_cpu(7));
    }

    #[test]
    fn test_cpumask_deserialize_none() {
        let json = r#"{
            "name": "test",
            "cpuset": "none",
            "matches": [[]],
            "kind": {
                "Open": {}
            }
        }"#;

        let spec: LayerSpec = serde_json::from_str(json).unwrap();
        assert!(spec.cpuset.is_some());
        let mask = spec.cpuset.as_ref().unwrap();
        assert!(mask.is_empty());
    }

    #[test]
    fn test_cpumask_deserialize_all() {
        let json = r#"{
            "name": "test",
            "cpuset": "all",
            "matches": [[]],
            "kind": {
                "Open": {}
            }
        }"#;

        let spec: LayerSpec = serde_json::from_str(json).unwrap();
        assert!(spec.cpuset.is_some());
        let mask = spec.cpuset.as_ref().unwrap();
        assert!(mask.is_full());
    }

    #[test]
    fn test_cpumask_deserialize_omitted() {
        let json = r#"{
            "name": "test",
            "matches": [[]],
            "kind": {
                "Open": {}
            }
        }"#;

        let spec: LayerSpec = serde_json::from_str(json).unwrap();
        assert!(spec.cpuset.is_none());
    }

    #[test]
    fn test_cpumask_serialize_deserialize_roundtrip() {
        let json = r#"{
            "name": "test",
            "cpuset": "0-7,16-23",
            "matches": [[]],
            "kind": {
                "Open": {}
            }
        }"#;

        let spec: LayerSpec = serde_json::from_str(json).unwrap();
        let serialized = serde_json::to_string(&spec).unwrap();
        let deserialized: LayerSpec = serde_json::from_str(&serialized).unwrap();

        assert_eq!(spec.cpuset.is_some(), deserialized.cpuset.is_some());
        if let (Some(original), Some(roundtrip)) = (&spec.cpuset, &deserialized.cpuset) {
            // Check that all CPUs have the same state in both masks
            for i in 0..original.len() {
                assert_eq!(
                    original.test_cpu(i),
                    roundtrip.test_cpu(i),
                    "CPU {} differs after roundtrip",
                    i
                );
            }
        }
    }

    #[test]
    fn test_cpumask_deserialize_invalid() {
        let json = r#"{
            "name": "test",
            "cpuset": "invalid-cpuset-format!!!",
            "matches": [[]],
            "kind": {
                "Open": {}
            }
        }"#;

        let result: Result<LayerSpec, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_cpumask_parsing_2_3() {
        let json = r#"{
            "name": "test",
            "cpuset": "2-3",
            "matches": [[]],
            "kind": {
                "Open": {}
            }
        }"#;

        let spec: LayerSpec = serde_json::from_str(json).unwrap();
        assert!(spec.cpuset.is_some());
        let mask = spec.cpuset.as_ref().unwrap();

        // Should have CPUs 2, 3 set
        assert!(!mask.test_cpu(0), "CPU 0 should not be set");
        assert!(!mask.test_cpu(1), "CPU 1 should not be set");
        assert!(mask.test_cpu(2), "CPU 2 should be set");
        assert!(mask.test_cpu(3), "CPU 3 should be set");
        assert!(!mask.test_cpu(4), "CPU 4 should not be set");
        assert_eq!(mask.weight(), 2, "Should have exactly 2 CPUs set");
    }

    #[test]
    fn test_cpumask_parsing_0xf0() {
        let json = r#"{
            "name": "test",
            "cpuset": "0xf0",
            "matches": [[]],
            "kind": {
                "Open": {}
            }
        }"#;

        let spec: LayerSpec = serde_json::from_str(json).unwrap();
        assert!(spec.cpuset.is_some());
        let mask = spec.cpuset.as_ref().unwrap();

        // 0xf0 = 11110000 in binary, should have CPUs 4,5,6,7 set
        assert!(!mask.test_cpu(0), "CPU 0 should not be set");
        assert!(!mask.test_cpu(1), "CPU 1 should not be set");
        assert!(!mask.test_cpu(2), "CPU 2 should not be set");
        assert!(!mask.test_cpu(3), "CPU 3 should not be set");
        assert!(mask.test_cpu(4), "CPU 4 should be set");
        assert!(mask.test_cpu(5), "CPU 5 should be set");
        assert!(mask.test_cpu(6), "CPU 6 should be set");
        assert!(mask.test_cpu(7), "CPU 7 should be set");
        assert_eq!(mask.weight(), 4, "Should have exactly 4 CPUs set");
    }
}
