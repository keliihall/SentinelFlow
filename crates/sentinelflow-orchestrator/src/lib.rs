//! Deterministic DAG planning and scheduling primitives for `SentinelFlow`.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use sentinelflow_schema::v1alpha1::{FailurePolicy, TaskSpec};
use serde::{Deserialize, Serialize};

/// One immutable planned DAG node.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlannedStep {
    /// Stable step name.
    pub name: String,
    /// Tool selected by the step.
    pub tool_ref: String,
    /// Declared dependencies.
    pub depends_on: Vec<String>,
    /// Topological execution level.
    pub level: usize,
    /// Failure propagation behavior.
    pub failure_policy: FailurePolicy,
}

/// Deterministic execution plan suitable for persistence as a snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskPlan {
    /// Task resource name.
    pub task_name: String,
    /// Stable topological order.
    pub execution_order: Vec<String>,
    /// Nodes grouped by concurrently eligible level.
    pub levels: Vec<Vec<String>>,
    /// Expanded node metadata.
    pub steps: Vec<PlannedStep>,
}

/// DAG planning error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanError {
    /// JSON-compatible field path.
    pub field: String,
    /// Non-sensitive explanation.
    pub message: String,
}

impl fmt::Display for PlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for PlanError {}

/// Validates and topologically plans a Task Spec.
///
/// # Errors
///
/// Rejects duplicate nodes or aliases, missing dependencies, invalid input
/// mappings, cycles, and nodes unreachable from a DAG root.
#[allow(clippy::too_many_lines)]
pub fn plan(task: &TaskSpec) -> Result<TaskPlan, PlanError> {
    let mut indexes = BTreeMap::new();
    let mut aliases = BTreeMap::new();
    for (index, step) in task.spec.steps.iter().enumerate() {
        if indexes.insert(step.name.as_str(), index).is_some() {
            return Err(error(
                format!("$.spec.steps[{index}].name"),
                "step names must be unique",
            ));
        }
        if let Some(alias) = &step.output_as {
            if aliases.insert(alias.as_str(), step.name.as_str()).is_some()
                || indexes.contains_key(alias.as_str())
            {
                return Err(error(
                    format!("$.spec.steps[{index}].outputAs"),
                    "output aliases must be unique and cannot shadow step names",
                ));
            }
        }
    }

    let mut indegree = vec![0_usize; task.spec.steps.len()];
    let mut dependents = vec![Vec::new(); task.spec.steps.len()];
    for (index, step) in task.spec.steps.iter().enumerate() {
        let mut unique = BTreeSet::new();
        for dependency in &step.depends_on {
            let Some(&dependency_index) = indexes.get(dependency.as_str()) else {
                return Err(error(
                    format!("$.spec.steps[{index}].dependsOn"),
                    format!("dependency does not exist: {dependency}"),
                ));
            };
            if dependency_index == index || !unique.insert(dependency_index) {
                return Err(error(
                    format!("$.spec.steps[{index}].dependsOn"),
                    "dependencies must be unique and cannot reference the current step",
                ));
            }
            indegree[index] += 1;
            dependents[dependency_index].push(index);
        }
        for (mapping_index, mapping) in step.input_from.iter().enumerate() {
            let source = indexes
                .get(mapping.from.as_str())
                .copied()
                .or_else(|| {
                    aliases
                        .get(mapping.from.as_str())
                        .and_then(|name| indexes.get(name).copied())
                })
                .ok_or_else(|| {
                    error(
                        format!("$.spec.steps[{index}].inputFrom[{mapping_index}].from"),
                        "input source does not exist",
                    )
                })?;
            if !unique.contains(&source) {
                return Err(error(
                    format!("$.spec.steps[{index}].inputFrom[{mapping_index}].from"),
                    "input source must also be declared in dependsOn",
                ));
            }
        }
    }

    let mut ready = VecDeque::new();
    let mut levels = vec![0_usize; task.spec.steps.len()];
    for (index, degree) in indegree.iter().enumerate() {
        if *degree == 0 {
            ready.push_back(index);
        }
    }
    let roots = ready.len();
    if roots == 0 {
        return Err(error("$.spec.steps", "DAG has no reachable root"));
    }

    let mut order = Vec::with_capacity(task.spec.steps.len());
    while let Some(index) = ready.pop_front() {
        order.push(index);
        for &dependent in &dependents[index] {
            levels[dependent] = levels[dependent].max(levels[index] + 1);
            indegree[dependent] -= 1;
            if indegree[dependent] == 0 {
                ready.push_back(dependent);
            }
        }
    }
    if order.len() != task.spec.steps.len() {
        let unreachable = task
            .spec
            .steps
            .iter()
            .enumerate()
            .filter(|(index, _)| !order.contains(index))
            .map(|(_, step)| step.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(error(
            "$.spec.steps",
            format!("cycle or unreachable steps detected: {unreachable}"),
        ));
    }

    let maximum_level = levels.iter().copied().max().unwrap_or(0);
    let mut grouped = vec![Vec::new(); maximum_level + 1];
    for &index in &order {
        grouped[levels[index]].push(task.spec.steps[index].name.clone());
    }
    Ok(TaskPlan {
        task_name: task.metadata.name.clone(),
        execution_order: order
            .iter()
            .map(|&index| task.spec.steps[index].name.clone())
            .collect(),
        levels: grouped,
        steps: order
            .iter()
            .map(|&index| {
                let step = &task.spec.steps[index];
                PlannedStep {
                    name: step.name.clone(),
                    tool_ref: step.tool_ref.clone(),
                    depends_on: step.depends_on.clone(),
                    level: levels[index],
                    failure_policy: step.failure_policy,
                }
            })
            .collect(),
    })
}

fn error(field: impl Into<String>, message: impl Into<String>) -> PlanError {
    PlanError {
        field: field.into(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use sentinelflow_schema::v1alpha1::{
        Metadata, OutputRetentionPolicy, ProtocolVersion, TaskExecutionPolicy, TaskInputMapping,
        TaskSpecData, TaskSpecKind, TaskStepSpec, TaskTargetSpec,
    };
    use serde_json::json;

    use super::*;

    fn task(steps: Vec<TaskStepSpec>) -> TaskSpec {
        TaskSpec {
            api_version: ProtocolVersion::V1Alpha1,
            kind: TaskSpecKind::Value,
            metadata: Metadata {
                name: "dag".to_owned(),
                namespace: None,
                uid: None,
                labels: BTreeMap::new(),
                annotations: BTreeMap::new(),
            },
            spec: TaskSpecData {
                authorization_scope: "fixture:local-only".to_owned(),
                targets: vec![TaskTargetSpec {
                    name: "fixture".to_owned(),
                    input: json!({"message": "fixture"}),
                }],
                steps,
                policy: TaskExecutionPolicy {
                    allowed_targets: vec!["fixture".to_owned()],
                    target_patterns: vec![],
                    approve_high_risk: false,
                    approval_ref: None,
                    timeout_seconds: Some(5),
                    max_concurrency: 2,
                    rate_limit_per_minute: 60,
                    time_windows: vec![],
                    output_retention: OutputRetentionPolicy {
                        days: 30,
                        retain_evidence: true,
                    },
                },
            },
            extensions: BTreeMap::new(),
        }
    }

    fn step(name: &str, dependencies: &[&str]) -> TaskStepSpec {
        TaskStepSpec {
            name: name.to_owned(),
            tool_ref: "example-echo".to_owned(),
            capability: "echo".to_owned(),
            depends_on: dependencies.iter().map(ToString::to_string).collect(),
            input_from: vec![],
            input: None,
            output_as: None,
            failure_policy: FailurePolicy::Stop,
        }
    }

    #[test]
    fn plans_parallel_levels_in_stable_order() {
        let result = plan(&task(vec![
            step("root", &[]),
            step("left", &["root"]),
            step("right", &["root"]),
            step("join", &["left", "right"]),
        ]))
        .unwrap();
        assert_eq!(
            result.levels,
            vec![vec!["root"], vec!["left", "right"], vec!["join"]]
        );
    }

    #[test]
    fn rejects_cycles_and_undeclared_input_sources() {
        assert!(
            plan(&task(vec![step("a", &["b"]), step("b", &["a"])]))
                .unwrap_err()
                .message
                .contains("root")
        );
        let mut downstream = step("downstream", &[]);
        downstream.input_from.push(TaskInputMapping {
            from: "root".to_owned(),
            pointer: "/spec/findings".to_owned(),
            target: "findings".to_owned(),
        });
        assert!(plan(&task(vec![step("root", &[]), downstream])).is_err());
    }
}
