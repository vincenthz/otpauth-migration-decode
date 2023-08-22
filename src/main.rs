use base64::Engine as _;
use clap::Parser;
use prost::Message;
use std::path::PathBuf;
use url::Url;

pub mod otpauth {
    include!(concat!(env!("OUT_DIR"), "/otp.migration.rs"));
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Name of the image file that contains a QR code
    file: PathBuf,
    #[arg(short, long)]
    as_url: bool,
}

fn main() {
    let args = Args::parse();

    let loc = &args.file;
    let img = image::open(loc).unwrap();

    let decoder = bardecoder::default_decoder();

    let results = decoder.decode(&img);

    let b = results[0].as_ref().expect("decoder QR code works").clone();
    let url = Url::parse(&b).expect("parsing decoded URL");
    if url.scheme() != "otpauth-migration" {
        println!("wrong scheme, got {}", url);
        return;
    }
    match url.query_pairs().next() {
        None => {}
        Some(p) => {
            if p.0 == "data" {
                let dat = p.1.to_owned();
                let b = base64::engine::general_purpose::STANDARD
                    .decode(dat.as_ref())
                    .unwrap();
                let b = bytes::Bytes::from(b);
                let m = otpauth::MigrationPayload::decode(b).unwrap();
                for params in m.otp_parameters {
                    if args.as_url {
                        todo!()
                    } else {
                        println!(
                            "name: {} -- issuer: {} -- alg: {} -- digits: {} -- type: {} -- secret: {}",
                            params.name,
                            params.issuer,
                            params.algorithm,
                            params.digits,
                            params.r#type,
                            base32::encode(
                                base32::Alphabet::RFC4648 { padding: false },
                                &params.secret
                            )
                        )
                    }
                }
            }
        }
    }
}
