use std::fs;
use std::time;
use std::io;
use std::io::prelude::*;
use std::io::Read;
use std::env;
use crypto::md5;
use crypto::sha1;
use crypto::sha2;

fn crypto_digest_generic<T: crypto::digest::Digest>(mut hasher: T, mut reader: io::BufReader<fs::File>, buffer: &mut [u8]) -> String {
    let mut len = reader.read(buffer).expect("");
    while len != 0 {
        hasher.input(&buffer[..len]);
        len = reader.read(buffer).expect("");
    }
    hasher.result_str()
}
fn crc32fast_digest(mut hasher: crc32fast::Hasher, mut reader: io::BufReader<fs::File>, buffer: &mut [u8]) -> String {
    let mut len = reader.read(buffer).expect("");
    while len != 0 {
        hasher.update(&buffer[..len]);
        len = reader.read(buffer).expect("");
    }
    format!("{:X}", hasher.finalize())
}
fn crc64fast_digest(mut hasher: crc64fast::Digest, mut reader: io::BufReader<fs::File>, buffer: &mut [u8]) -> String {
    let mut len = reader.read(buffer).expect("");
    while len != 0 {
        hasher.write(&buffer[..len]);
        len = reader.read(buffer).expect("");
    }
    format!("{:X}", hasher.sum64())
}

fn pause() {
    let mut stdin = io::stdin();
    let mut stdout = io::stdout();

    write!(stdout, "\nPress any key to continue...").unwrap();
    stdout.flush().unwrap();

    let _ = stdin.read(&mut [0u8]).unwrap();
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() == 1 {
        println!("rhasher - A quick way of generating hashes from known crypto algorithms.\n");

        println!("Usage: rhasher file [hash]");
        println!("\tfile: The path to your file.");
        println!("\thash: The hash you wish to compute. Default is MD5.");
        println!("\t\tMD5\n\t\tSHA1\n\t\tSHA224\n\t\tSHA256\n\t\tSHA384\n\t\tSHA512\n\t\tCRC32\n\t\tCRC64");
    } else {
        let hash_type: &str = if args.len() >= 3 {
            args[2].as_str()
        } else {
            "MD5"
        };
        let file = fs::File::open(&args[1])?;
        let reader = io::BufReader::new(file);
        let mut buffer: Vec<u8> = vec![0; 0x100000]; // TODO: Need to toy around with the buffer sizes to see what is fastest

        println!("Algorithm: {}",hash_type);
        println!("File: {}",args[1]);

        let start_time = time::Instant::now();
        let result = match hash_type {
            "MD5"    => crypto_digest_generic(md5::Md5::new(),     reader, &mut buffer), 
            "SHA1"   => crypto_digest_generic(sha1::Sha1::new(),   reader, &mut buffer), 
            "SHA224" => crypto_digest_generic(sha2::Sha224::new(), reader, &mut buffer), 
            "SHA256" => crypto_digest_generic(sha2::Sha256::new(), reader, &mut buffer), 
            "SHA384" => crypto_digest_generic(sha2::Sha384::new(), reader, &mut buffer), 
            "SHA512" => crypto_digest_generic(sha2::Sha512::new(), reader, &mut buffer), 
            "CRC32"  => crc32fast_digest(crc32fast::Hasher::new(), reader, &mut buffer), 
            "CRC64"  => crc64fast_digest(crc64fast::Digest::new(), reader, &mut buffer),
            _ => unimplemented!(""),
        };
        let end_time = time::Instant::now();

        let result_upper = result.to_ascii_uppercase();

        println!("Hash: {}",result_upper);
        println!("Time: {:?}", (end_time - start_time));
    }
    
    pause();
    Ok(())
}