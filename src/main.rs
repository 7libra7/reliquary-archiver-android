use std::fs::File;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::io::{BufRead, BufReader};
use std::sync::Mutex;
use std::time::Duration;

use clap::Parser;
use reliquary::network::gen::command_id::{PlayerLoginFinishScRsp, PlayerLoginScRsp};
use reliquary::network::{ConnectionPacket, GamePacket, GameSniffer};
use tracing::{debug, error, info, instrument, trace, warn};
use tracing_subscriber::{prelude::*, EnvFilter, Layer, Registry};

use reliquary_archiver::export::database::Database;
use reliquary_archiver::export::fribbels::OptimizerExporter;
use reliquary_archiver::export::Exporter;

const PACKET_FILTER: &str = "udp and portrange 23301-23302";

#[derive(Parser, Debug)]
struct Args {
    #[arg(default_value = "archive_output.json")]
    /// Path to output .json file to
    output: PathBuf,
    /// Read packets from .pcap file instead of capturing live packets  
    #[arg(long)]
    pcap: Option<PathBuf>,
    /// How long to wait in seconds until timeout is triggered for live captures
    #[arg(long, default_value_t = 120)]
    timeout: u64,
    /// How verbose the output should be, can be set up to 3 times. Has no effect if RUST_LOG is set
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
    /// Path to output log to
    #[arg(short, long)]
    log_path: Option<PathBuf>,
    /// Network interface to capture from
    #[arg(short, long, default_value = "wlan0")]
    interface: String,
}

fn main() {
    color_eyre::install().unwrap();
    let args = Args::parse();

    tracing_init(&args);

    debug!(?args);

    let database = Database::new();
    let sniffer = GameSniffer::new().set_initial_keys(database.keys.clone());
    let exporter = OptimizerExporter::new(database);

    let export = match args.pcap {
        Some(_) => file_capture(&args, exporter, sniffer),
        None => live_capture(&args, exporter, sniffer),
    };

    if let Some(export) = export {
        let file = File::create(&args.output).unwrap();
        serde_json::to_writer_pretty(&file, &export).unwrap();
        info!(
            "wrote output to {}",
            &args.output.canonicalize().unwrap().display()
        );
    } else {
        warn!("skipped writing output");
    }

    if let Some(log_path) = args.log_path {
        info!("wrote logs to {}", log_path.display());
    }

    info!("press enter to close");
    std::io::stdin().read_line(&mut String::new()).unwrap();
}

fn tracing_init(args: &Args) {
    let env_filter = EnvFilter::builder()
        .with_default_directive(
            match args.verbose {
                0 => "reliquary_archiver=info",
                1 => "info",
                2 => "debug",
                _ => "trace",
            }
            .parse()
            .unwrap(),
        )
        .from_env_lossy();

    let stdout_log = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_filter(env_filter);

    let subscriber = Registry::default().with(stdout_log);

    let file_log = if let Some(log_path) = &args.log_path {
        let log_file = File::create(log_path).unwrap();
        let file_log = tracing_subscriber::fmt::layer()
            .json()
            .with_writer(Mutex::new(log_file))
            .with_filter(tracing::level_filters::LevelFilter::TRACE);
        Some(file_log)
    } else {
        None
    };

    let subscriber = subscriber.with(file_log);

    tracing::subscriber::set_global_default(subscriber).expect("unable to set up logging");
}

#[instrument(skip_all)]
fn file_capture<E>(args: &Args, mut exporter: E, mut sniffer: GameSniffer) -> Option<E::Export>
where
    E: Exporter,
{
    let mut capture =
        pcap::Capture::from_file(args.pcap.as_ref().unwrap()).expect("could not read pcap file");

    capture.filter(PACKET_FILTER, false).unwrap();

    let mut invalid = 0;

    info!("capturing");
    while let Ok(packet) = capture.next_packet() {
        if let Some(GamePacket::Commands(commands)) = sniffer.receive_packet(packet.data.to_vec()) {
            if commands.is_empty() {
                invalid += 1;

                // FIXME: disable the invalid packet checks until the situation in
                // reliquary lib has been resolved
                
                // if invalid >= 50 {
                //     error!("received 50 packets that could not be segmented");
                //     warn!("you probably started capturing when you were already in-game");
                //     warn!("the capture needs to start on the main menu screen");
                //     warn!("log out then log back in");
                //     return None;
                // }
            } else {
                invalid = 0.max(invalid - 1);
                for command in commands {
                    exporter.read_command(command);
                }

                if exporter.is_finished() {
                    info!("retrieved all relevant packets, stop capturing");
                    break;
                }
            }
        }
    }

    Some(exporter.export())
}

#[instrument(skip_all)]
fn live_capture<E>(args: &Args, mut exporter: E, mut sniffer: GameSniffer) -> Option<E::Export>
where
    E: Exporter,
{
    info!("instructions: go to main menu screen and go to the \"Click to Start\" screen");
    info!("listening with a timeout of {} seconds...", args.timeout);

    let tcpdump = Command::new("tcpdump")
        .args([
            "-i", &args.interface,
            "-w", "-", // Write to stdout
            "-U", // Packet-buffered output
            "udp", "portrange", "23301-23302"
        ])
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to start tcpdump. Make sure tcpdump is installed and you have root permissions.");

    let stdout = tcpdump.stdout.unwrap();
    let mut reader = BufReader::new(stdout);
    let mut buffer = vec![0; 65535]; // Buffer per contenere un pacchetto intero
    let mut invalid = 0;

    let start_time = std::time::Instant::now();

    while let Ok(n) = reader.read(&mut buffer) {
        if n == 0 {
            break; // EOF
        }

        let data = &buffer[..n];

        if start_time.elapsed() > Duration::from_secs(args.timeout) {
            warn!("Capture timeout reached");
            break;
        }

        match sniffer.receive_packet(data.to_vec()) {
            Some(GamePacket::Connection(c)) => {
                match c {
                    ConnectionPacket::HandshakeEstablished => {
                        info!("detected connection established");
                    }
                    ConnectionPacket::Disconnected => {}
                    _ => {}
                }
            }
            Some(GamePacket::Commands(commands)) => {
                if commands.is_empty() {
                    invalid += 1;
                } else {
                    invalid = 0.max(invalid - 1);

                    for command in commands {
                        if command.command_id == PlayerLoginScRsp {
                            info!("detected login");
                        }

                        if command.command_id == PlayerLoginFinishScRsp {
                            info!("detected login end, assume initialization is finished");
                            return Some(exporter.export());
                        }

                        exporter.read_command(command);
                    }

                    if exporter.is_finished() {
                        info!("retrieved all relevant packets, stop listening");
                        return Some(exporter.export());
                    }
                }
            }
            _ => {}
        }
    }

    Some(exporter.export())
}
