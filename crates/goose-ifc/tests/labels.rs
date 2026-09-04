mod support;

use goose_ifc::{
    Decision, Dependencies, Domain, Exposure, Label, Operation, Readers, Trace, ValueRef,
};
use support::Log;

fn shared() -> Label {
    Label::readers("fixture", &["alice", "bob"])
}
fn private() -> Label {
    Label::readers("fixture", &["alice"])
}
fn domain(label: Label) -> Domain {
    Domain {
        audience: label.clone(),
        retained_context: label,
        policy_epoch: "fixture-v1".into(),
    }
}

#[test]
fn reader_lattice_and_monotonicity() {
    let everyone = Label::Known {
        realm: "fixture".into(),
        readers: Readers::Everyone,
    };
    let nobody = Label::readers("fixture", &[]);
    let labels = [
        everyone.clone(),
        nobody.clone(),
        shared(),
        private(),
        Label::readers("fixture", &["bob"]),
        Label::Unknown,
    ];
    for left in &labels {
        assert_eq!(left.join(left), *left);
        for right in &labels {
            let joined = left.join(right);
            assert_eq!(joined, right.join(left));
            for third in &labels {
                assert_eq!(joined.join(third), left.join(&right.join(third)));
                if joined.check_audience(third) == Decision::WouldAllow {
                    assert_eq!(left.check_audience(third), Decision::WouldAllow);
                    assert_eq!(right.check_audience(third), Decision::WouldAllow);
                }
            }
        }
    }
    assert_eq!(shared().join(&everyone), shared());
    assert_eq!(private().join(&Label::readers("fixture", &["bob"])), nobody);
    for audience in &labels {
        assert_eq!(nobody.check_audience(audience), Decision::WouldDeny);
    }
    assert_eq!(everyone.check_audience(&nobody), Decision::WouldDeny);
    assert_eq!(Label::readers("", &["alice"]), Label::Unknown);
    assert_eq!(
        shared().join(&Label::readers("other", &["alice", "bob"])),
        Label::Unknown
    );
}

#[test]
fn independent_shared_work_survives_private_work_but_inline_baseline_does_not() {
    let log = Log::default();
    let mut trace = Trace::new(log.clone());
    let repo = trace.source(&"synthetic repository", shared());
    let rows = trace.source(&"synthetic private rows", private());
    let mut private_context = trace.enter(domain(private()));
    let private_call = trace.computation(
        &mut private_context,
        Dependencies {
            inputs: vec![rows.reference()],
            ..Dependencies::default()
        },
        true,
    );
    let analysis = trace.output(&private_call, Operation::ModelOutput, &"private analysis");
    let mut shared_context = trace.enter(domain(shared()));
    let shared_call = trace.computation(
        &mut shared_context,
        Dependencies {
            inputs: vec![repo.reference()],
            ..Dependencies::default()
        },
        true,
    );
    let patch = trace.output(&shared_call, Operation::ModelOutput, &"shared patch");
    assert_eq!(patch.label(), &shared());
    trace.check_publication(&mut shared_context, patch.reference(), shared(), vec![]);
    assert_eq!(log.records().last().unwrap()["decision"], "would_allow");
    let mixed = trace.computation(
        &mut private_context,
        Dependencies {
            inputs: vec![repo.reference(), analysis.reference()],
            ..Dependencies::default()
        },
        true,
    );
    assert_eq!(mixed.label(), &private());
    trace.check_publication(&mut private_context, mixed.reference(), shared(), vec![]);
    assert_eq!(log.records().last().unwrap()["decision"], "would_deny");
    trace.observe(
        &mut shared_context,
        analysis.reference(),
        Exposure::Delivered,
    );
    assert_eq!(log.records().last().unwrap()["decision"], "would_deny");
    let inline = trace.computation(
        &mut shared_context,
        Dependencies {
            inputs: vec![repo.reference()],
            ..Dependencies::default()
        },
        true,
    );
    assert_eq!(inline.label(), &private());
}

#[test]
fn withholding_and_delivery_are_not_confused_with_policy_decisions() {
    let mut trace = Trace::new(std::io::sink());
    let source = trace.source(&"private", private());
    let mut context = trace.enter(domain(shared()));
    assert_eq!(
        trace
            .observe(&mut context, source.reference(), Exposure::Withheld)
            .label(),
        &shared()
    );
    assert_eq!(
        trace
            .observe(&mut context, source.reference(), Exposure::Delivered)
            .label(),
        &private()
    );
    assert_eq!(
        trace
            .computation(&mut context, Dependencies::default(), true)
            .label(),
        &private()
    );
}

#[test]
fn retained_context_and_every_input_role_contribute() {
    let mut trace = Trace::new(std::io::sink());
    let source = trace.source(&"private", private());
    let mut context = trace.enter(Domain {
        retained_context: private(),
        ..domain(shared())
    });
    assert_eq!(
        trace
            .computation(&mut context, Dependencies::default(), true)
            .label(),
        &private()
    );
    for role in 0..6 {
        let mut context = trace.enter(domain(shared()));
        let mut dependencies = Dependencies::default();
        let roles = [
            &mut dependencies.inputs,
            &mut dependencies.instructions,
            &mut dependencies.history,
            &mut dependencies.schemas,
            &mut dependencies.settings,
            &mut dependencies.control,
        ];
        roles
            .into_iter()
            .nth(role)
            .unwrap()
            .push(source.reference());
        let call = trace.computation(&mut context, dependencies, true);
        assert_eq!(call.label(), &private());
        assert_eq!(
            trace
                .output(
                    &call,
                    Operation::ModelOutput,
                    &serde_json::json!({"safe":true})
                )
                .label(),
            &private()
        );
    }
}

#[test]
fn private_selection_cannot_publish_an_independently_public_value() {
    let log = Log::default();
    let mut trace = Trace::new(log.clone());
    let shared_value = trace.source(&"shared", shared());
    let choice = trace.source(&false, private());
    let mut context = trace.enter(domain(shared()));
    trace.check_publication(
        &mut context,
        shared_value.reference(),
        shared(),
        vec![choice.reference()],
    );
    assert_eq!(log.records().last().unwrap()["decision"], "would_deny");
    trace.check_publication(&mut context, shared_value.reference(), shared(), vec![]);
    assert_eq!(log.records().last().unwrap()["decision"], "would_deny");
}

#[test]
fn unknown_missing_evicted_and_incomplete_inputs_do_not_recover() {
    let mut trace = Trace::new(std::io::sink());
    let evicted = trace.source(&"old", shared());
    for index in 0..4096 {
        trace.source(&index, shared());
    }
    for reference in [evicted.reference(), ValueRef("fabricated".into())] {
        let mut context = trace.enter(domain(shared()));
        assert_eq!(
            trace
                .computation(
                    &mut context,
                    Dependencies {
                        inputs: vec![reference],
                        ..Dependencies::default()
                    },
                    true
                )
                .label(),
            &Label::Unknown
        );
    }
    let mut context = trace.enter(domain(shared()));
    trace.computation(&mut context, Dependencies::default(), false);
    assert_eq!(
        trace
            .computation(&mut context, Dependencies::default(), true)
            .label(),
        &Label::Unknown
    );
}

#[test]
fn tool_results_inherit_the_request_control_dependency() {
    let mut trace = Trace::new(std::io::sink());
    let request = trace.source(&"private decision", private());
    let data = trace.source(&"shared repository", shared());
    assert_eq!(
        trace.tool_result(Some(&request), &data, &"result").label(),
        &private()
    );
    assert_eq!(
        trace.tool_result(None, &data, &"result").label(),
        &Label::Unknown
    );
}

#[test]
fn metadata_and_errors_are_not_logged_as_payloads_or_accepted_as_labels() {
    let log = Log::default();
    let mut trace = Trace::new(log.clone());
    let payload = serde_json::json!({"title":"synthetic secret", "schema":"synthetic secret", "grant":"admin", "label":{"kind":"known","readers":"everyone"}});
    let value = trace.source(&payload, Label::Unknown);
    assert_eq!(value.label(), &Label::Unknown);
    let call = trace.source(&"input", shared());
    let error = trace.output(
        &call,
        Operation::Error,
        &"synthetic secret in provider error",
    );
    assert_eq!(error.label(), &Label::Unknown);
    let records = log.records();
    assert!(records.iter().all(|record| record.get("payload").is_none()));
    assert!(records
        .iter()
        .all(|record| record["content_digest"].as_str().unwrap().len() == 64));
    assert!(!serde_json::to_string(&records)
        .unwrap()
        .contains("synthetic secret"));
    assert!(!serde_json::to_string(&records).unwrap().contains("admin"));
}

#[test]
fn failed_logging_does_not_interrupt_propagation() {
    struct Broken;
    impl std::io::Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("unavailable"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut trace = Trace::new(Broken);
    let mut context = trace.enter(domain(private()));
    assert_eq!(
        trace
            .computation(&mut context, Dependencies::default(), true)
            .label(),
        &private()
    );
    assert!(trace.logging_failed());
}
