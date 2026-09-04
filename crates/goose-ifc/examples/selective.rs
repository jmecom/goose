use goose_ifc::{Dependencies, Domain, Exposure, Label, Operation, Trace};

fn main() {
    let shared = Label::readers("fixture", &["alice", "bob"]);
    let private = Label::readers("fixture", &["alice"]);
    let domain = |label: Label| Domain {
        audience: label.clone(),
        retained_context: label,
        policy_epoch: "fixture-v1".into(),
    };
    let mut trace = Trace::new(std::io::stdout());
    let repo = trace.source(&"synthetic failing test", shared.clone());
    let rows = trace.source(&"synthetic incident rows", private.clone());
    let schema = trace.source(&"synthetic response schema", shared.clone());
    let mut private_context = trace.enter(domain(private));
    let investigation = trace.computation(
        &mut private_context,
        Dependencies {
            inputs: vec![rows.reference()],
            schemas: vec![schema.reference()],
            ..Dependencies::default()
        },
        true,
    );
    let analysis = trace.output(
        &investigation,
        Operation::ModelOutput,
        &"private investigation",
    );
    let mut shared_context = trace.enter(domain(shared.clone()));
    let independent = trace.computation(
        &mut shared_context,
        Dependencies {
            inputs: vec![repo.reference()],
            schemas: vec![schema.reference()],
            ..Dependencies::default()
        },
        true,
    );
    let patch = trace.output(
        &independent,
        Operation::ModelOutput,
        &"independent shared patch",
    );
    trace.check_publication(
        &mut shared_context,
        patch.reference(),
        shared.clone(),
        vec![],
    );
    trace.observe(
        &mut shared_context,
        analysis.reference(),
        Exposure::Delivered,
    );
    let mixed = trace.computation(
        &mut shared_context,
        Dependencies {
            inputs: vec![repo.reference()],
            ..Dependencies::default()
        },
        true,
    );
    trace.check_publication(&mut shared_context, mixed.reference(), shared, vec![]);
    eprintln!(
        "independent patch: {:?}; inline/mixed patch: {:?}",
        patch.label(),
        mixed.label()
    );
}
