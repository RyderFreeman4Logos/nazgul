#![cfg_attr(
    any(feature = "wasm", target_arch = "wasm32", not(feature = "cpu-time")),
    allow(dead_code, unused_imports)
)]

#[cfg(all(
    feature = "cpu-time",
    not(feature = "wasm"),
    not(target_arch = "wasm32")
))]
use nazgul::pow::VerificationCostModel;

#[cfg(all(
    feature = "cpu-time",
    not(feature = "wasm"),
    not(target_arch = "wasm32")
))]
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

#[cfg(any(feature = "wasm", target_arch = "wasm32", not(feature = "cpu-time")))]
fn main() {
    // The time model binary is only meaningful on native targets; provide a no-op for wasm builds.
}
