use base64::Engine as _;
use prost::Message;
use url::Url;

pub mod otpauth {
    include!(concat!(env!("OUT_DIR"), "/otp.migration.rs"));
}

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    let loc = args[1].clone();
    let img = image::open(loc).unwrap();

    let decoder = bardecoder::default_decoder();

    let results = decoder.decode(&img);

    let b = results[0].as_ref().expect("decoder QR code works").clone();
    let url = Url::parse(&b).expect("parsing decoded URL");
    if url.scheme() != "otpauth-migration" {
        println!("wrong scheme for {}", url);
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
                    println!(
                        "name: {} -- alg: {} -- digits: {} -- type: {} -- secret: {}",
                        params.name,
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
