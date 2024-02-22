mod ips_file;

use std::env;
use std::error::Error;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read};
use std::process::Command;

use ips_file::IPSFile;
use rustc_demangle::demangle_stream;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <crash-report> <dsym>", args[0]);
        return Ok(());
    }

    let path = &args[1];
    let mut file = File::open(path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;

    let file = IPSFile::parse(contents)?;
    let dsym_uuid_output = Command::new("dwarfdump")
        .arg("--uuid")
        .arg(&args[2])
        .output()?;

    let uuid = String::from_utf8(dsym_uuid_output.stdout)?
        .lines()
        .next()
        .ok_or("No UUID found in dwarfdump output")?
        .split_whitespace()
        .nth(1)
        .ok_or("Failed to extract UUID")?
        .to_string();

    let uuid_lowercase = uuid.to_lowercase();
    let Some((image_index, _)) = file
        .body
        .used_images
        .iter()
        .enumerate()
        .find(|(_, image)| image.uuid.to_lowercase() == uuid_lowercase)
    else {
        return Err(format!("{} does not contain debug symbols for this crash", &args[2]).into());
    };

    if let Some(thread) = file.faulting_thread() {
        let image_offsets: Vec<String> = thread
            .frames
            .iter()
            .map(|frame| format!("0x{:x}", frame.image_offset))
            .collect();

        let dsym_path = &args[2];
        let output = Command::new("atos")
            .arg("-o")
            .arg(dsym_path)
            .arg("-offset")
            .arg("-inlineFrames")
            .arg("-fullPath")
            .args(&image_offsets)
            .output()?;
        let mut processed_output: Vec<u8> = Vec::new();
        for line in String::from_utf8_lossy(&output.stdout).split("\n") {
            dbg!(&line);
            let Some((symbol, rest)) = line.split_once("(in") else {
                processed_output.extend_from_slice(line.as_bytes());
                processed_output.push(b'\n');
                continue;
            };
            let Some((_dsym, source)) = rest.split_once("(/") else {
                processed_output.extend_from_slice(line.as_bytes());
                processed_output.push(b'\n');
                continue;
            };

            if source.contains("/crates/") {
                let crate_path = source.splitn(2, "/crates/").nth(1).unwrap_or("");
                processed_output.extend_from_slice("crates/".as_bytes());
                processed_output.extend_from_slice(crate_path.trim_end_matches(")").as_bytes());
            } else {
                processed_output.push(b'/');
                processed_output.extend_from_slice(source.trim_end_matches(")").as_bytes());
            };
            processed_output.push(b':');
            processed_output.push(b'\t');
            processed_output.extend_from_slice(symbol.trim().as_bytes());
            processed_output.push(b'\n');
        }
        let mut stdout_bufread = BufReader::new(&processed_output[..]);
        let mut temp = Vec::new();
        let mut temp_buffered = BufWriter::new(&mut temp);

        demangle_stream(&mut stdout_bufread, &mut temp_buffered, false)?;
        drop(temp_buffered);

        let demangled_output = String::from_utf8(temp)?;
        let frames: Vec<String> = demangled_output
            .split("\n\n")
            .map(|s| s.to_string())
            .collect();

        for (frame, output) in thread.frames.iter().zip(frames.iter()) {
            if frame.symbol.as_ref().map_or(false, |sym| {
                sym.contains("pthread_kill")
                    || sym.contains("panic")
                    || sym.contains("backtrace")
                    || sym.contains("rust_begin_unwind")
                    || sym.contains("abort")
            }) {
                continue;
            }
            if frame.image_index == image_index as i64 {
                println!("{}", output);
            } else {
                println!(
                    "{}\t{}",
                    file.body.used_images[frame.image_index as usize]
                        .name
                        .clone()
                        .unwrap_or_default(),
                    frame.symbol.clone().unwrap_or_default(),
                )
            }
        }
    }

    Ok(())
}
