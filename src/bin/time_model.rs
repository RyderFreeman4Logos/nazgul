use nazgul::blsag::VerificationTimeModel;

fn main() {
    // Generate the hardware-specific performance model by running the heavy benchmark.
    let model = VerificationTimeModel::generate_heavy();

    println!("\n--- Generated VerificationTimeModel Coefficients ---");
    println!("# Copy these values to create your model instance or save as JSON.");
    println!("nanos_per_member: {}", model.nanos_per_member);
    println!("nanos_per_byte: {}", model.nanos_per_byte);
    println!("fixed_overhead_nanos: {}", model.fixed_overhead_nanos);

    // Provide a JSON representation that the user can copy.
    // This avoids adding a direct dependency on serde_json to this binary.
    println!("\n# Example JSON representation:");
    println!("{{");
    println!("  \"nanos_per_member\": {},", model.nanos_per_member);
    println!("  \"nanos_per_byte\": {},", model.nanos_per_byte);
    println!("  \"fixed_overhead_nanos\": {}", model.fixed_overhead_nanos);
    println!("}} ");
}