use nazgul::pow::VerificationCostModel;

fn main() {
    // Generate the hardware-specific performance model by running the heavy benchmark.
    let model = VerificationCostModel::generate_heavy();

    println!("\n--- Generated VerificationCostModel Coefficients ---");
    println!("# Copy these values to create your model instance or save as JSON.");
    println!("cpu_nanos_per_member: {}", model.cpu_nanos_per_member);
    println!("cpu_nanos_per_byte: {}", model.cpu_nanos_per_byte);
    println!("fixed_cpu_nanos: {}", model.fixed_cpu_nanos);

    // Provide a JSON representation that the user can copy.
    // This avoids adding a direct dependency on serde_json to this binary.
    println!("\n# Example JSON representation:");
    println!("{{");
    println!(
        "  \"cpu_nanos_per_member\": {},",
        model.cpu_nanos_per_member
    );
    println!("  \"cpu_nanos_per_byte\": {},", model.cpu_nanos_per_byte);
    println!("  \"fixed_cpu_nanos\": {}", model.fixed_cpu_nanos);
    println!("}} ");
}
