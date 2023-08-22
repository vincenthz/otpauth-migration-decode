fn main() -> Result<(), std::io::Error> {
    prost_build::compile_protos(&["proto/otpauth.proto"], &["proto/"])?;
    Ok(())
}
