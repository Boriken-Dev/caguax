//! Sessions written to a capture file as TCP connections.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::time::Duration;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::SystemTime;

use pcap_file::DataLink;
use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
use pcap_file::pcapng::PcapNgWriter;
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;

use super::{RecordError, Recorder, Sender, Session};
use crate::error::{Error, Result, config};

const SYN: u8 = 0x02;
const FIN: u8 = 0x01;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;

/// The capture file format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum PcapFormat {
    /// The classic `pcap` format.
    #[default]
    Pcap,
    /// `pcapng`.
    Pcapng,
}

#[derive(Clone)]
struct Shared(Arc<Mutex<BufWriter<File>>>);

impl Write for Shared {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .write(data)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .flush()
    }
}

enum Writer {
    Pcap(PcapWriter<Shared>),
    Ng(PcapNgWriter<Shared>),
}

struct Flow {
    client: SocketAddr,
    server: SocketAddr,
    seq: [u32; 2],
}

struct State {
    writer: Writer,
    flows: BTreeMap<u64, Flow>,
}

/// Writes every session to a capture file as a TCP connection between the client's address and
/// the address the proxy connected to. The octets are those the proxy relayed, so a TLS route is
/// recorded in plaintext on its TLS port: in Wireshark, *Decode As* HTTP. Thread-safe; the file is
/// flushed by [`close`](Self::close) and on drop. Needs feature `pcap`.
pub struct PcapRecorder {
    shared: Shared,
    state: Mutex<State>,
    mss: usize,
}

impl core::fmt::Debug for PcapRecorder {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PcapRecorder")
            .field("mss", &self.mss)
            .finish_non_exhaustive()
    }
}

impl PcapRecorder {
    /// Creates (or truncates) the capture file at `path`.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when the file cannot be written.
    pub fn create(path: impl AsRef<Path>, format: PcapFormat) -> Result<Self> {
        let file = File::create(path)?;
        let shared = Shared(Arc::new(Mutex::new(BufWriter::new(file))));
        let writer = match format {
            PcapFormat::Pcap => Writer::Pcap(
                PcapWriter::with_header(
                    shared.clone(),
                    PcapHeader {
                        datalink: DataLink::ETHERNET,
                        ..PcapHeader::default()
                    },
                )
                .map_err(write_error)?,
            ),
            PcapFormat::Pcapng => {
                let mut writer = PcapNgWriter::new(shared.clone()).map_err(write_error)?;
                writer
                    .write_pcapng_block(InterfaceDescriptionBlock {
                        linktype: DataLink::ETHERNET,
                        snaplen: 0,
                        options: Vec::new(),
                    })
                    .map_err(write_error)?;
                Writer::Ng(writer)
            }
        };
        Ok(Self {
            shared,
            state: Mutex::new(State {
                writer,
                flows: BTreeMap::new(),
            }),
            mss: 1460,
        })
    }

    /// The most payload octets in one recorded segment (default 1460).
    ///
    /// # Errors
    ///
    /// [`Error::Config`] for zero.
    pub fn mss(mut self, mss: usize) -> Result<Self> {
        if mss == 0 {
            return Err(config("a segment size is above zero"));
        }
        self.mss = mss;
        Ok(self)
    }

    /// Flushes the file and ends the recording.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when the flush fails.
    pub fn close(self) -> Result<()> {
        let mut shared = self.shared.clone();
        shared.flush()?;
        Ok(())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn put(&self, state: &mut State, frame: &[u8]) -> core::result::Result<(), RecordError> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);
        let length = u32::try_from(frame.len()).map_err(|_| RecordError::new("frame too long"))?;
        match &mut state.writer {
            Writer::Pcap(writer) => {
                let packet = PcapPacket::new(now, length, frame)
                    .map_err(|_| RecordError::new("the packet is not writable"))?;
                writer
                    .write_packet(&packet)
                    .map_err(|_| RecordError::new("the capture file cannot be written"))?;
            }
            Writer::Ng(writer) => {
                writer
                    .write_pcapng_block(EnhancedPacketBlock {
                        interface_id: 0,
                        timestamp: now,
                        original_len: length,
                        data: frame.into(),
                        options: Vec::new(),
                    })
                    .map_err(|_| RecordError::new("the capture file cannot be written"))?;
            }
        }
        Ok(())
    }

    fn send(
        &self,
        state: &mut State,
        id: u64,
        from: Sender,
        flags: u8,
        payload: &[u8],
    ) -> core::result::Result<(), RecordError> {
        let Some(flow) = state.flows.get_mut(&id) else {
            return Ok(());
        };
        let (own, other) = if from == Sender::Client {
            (0, 1)
        } else {
            (1, 0)
        };
        let (source, target) = if from == Sender::Client {
            (flow.client, flow.server)
        } else {
            (flow.server, flow.client)
        };
        let frame = frame(
            source,
            target,
            flow.seq[own],
            flow.seq[other],
            flags,
            payload,
            from,
        );
        let consumed =
            u32::try_from(payload.len()).unwrap_or(u32::MAX) + u32::from(flags & (SYN | FIN) != 0);
        flow.seq[own] = flow.seq[own].wrapping_add(consumed);
        self.put(state, &frame)
    }
}

fn write_error(_error: impl core::fmt::Debug) -> Error {
    Error::Io(std::io::Error::other("the capture file cannot be written"))
}

fn mapped(address: SocketAddr) -> (IpAddr, u16) {
    (address.ip(), address.port())
}

fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    let mut carry: Option<u8> = None;
    for part in parts {
        for byte in part.iter().copied() {
            match carry.take() {
                Some(high) => sum += u32::from(u16::from_be_bytes([high, byte])),
                None => carry = Some(byte),
            }
        }
    }
    if let Some(high) = carry {
        sum += u32::from(u16::from_be_bytes([high, 0]));
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn frame(
    source: SocketAddr,
    target: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
    from: Sender,
) -> Vec<u8> {
    let (source_ip, source_port) = mapped(source);
    let (target_ip, target_port) = mapped(target);
    let v6 = source_ip.is_ipv6() || target_ip.is_ipv6();
    let mut tcp = Vec::with_capacity(20 + payload.len());
    tcp.extend_from_slice(&source_port.to_be_bytes());
    tcp.extend_from_slice(&target_port.to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&ack.to_be_bytes());
    tcp.push(0x50);
    tcp.push(flags);
    tcp.extend_from_slice(&0xFFFF_u16.to_be_bytes());
    tcp.extend_from_slice(&[0, 0, 0, 0]);
    tcp.extend_from_slice(payload);
    let macs: [[u8; 6]; 2] = [[2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2]];
    let (destination_mac, source_mac) = if from == Sender::Client {
        (macs[1], macs[0])
    } else {
        (macs[0], macs[1])
    };
    let mut out = Vec::with_capacity(54 + payload.len());
    out.extend_from_slice(&destination_mac);
    out.extend_from_slice(&source_mac);
    if v6 {
        let to_v6 = |ip: IpAddr| match ip {
            IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
            IpAddr::V6(v6) => v6.octets(),
        };
        let (src, dst) = (to_v6(source_ip), to_v6(target_ip));
        let length = (tcp.len() as u16).to_be_bytes();
        let pseudo = [&src[..], &dst[..], &[0, 0], &length, &[0, 0, 0, 6]].concat();
        let sum = checksum(&[&pseudo, &tcp]);
        tcp[16..18].copy_from_slice(&sum.to_be_bytes());
        out.extend_from_slice(&0x86DD_u16.to_be_bytes());
        out.extend_from_slice(&[0x60, 0, 0, 0]);
        out.extend_from_slice(&length);
        out.extend_from_slice(&[6, 64]);
        out.extend_from_slice(&src);
        out.extend_from_slice(&dst);
    } else {
        let to_v4 = |ip: IpAddr| match ip {
            IpAddr::V4(v4) => v4.octets(),
            IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED.octets(),
        };
        let (src, dst) = (to_v4(source_ip), to_v4(target_ip));
        let length = (tcp.len() as u16).to_be_bytes();
        let pseudo = [&src[..], &dst[..], &[0, 6], &length].concat();
        let sum = checksum(&[&pseudo, &tcp]);
        tcp[16..18].copy_from_slice(&sum.to_be_bytes());
        let total = ((20 + tcp.len()) as u16).to_be_bytes();
        let mut header = [
            0x45, 0, total[0], total[1], 0, 0, 0x40, 0, 64, 6, 0, 0, src[0], src[1], src[2],
            src[3], dst[0], dst[1], dst[2], dst[3],
        ];
        let header_sum = checksum(&[&header]);
        header[10..12].copy_from_slice(&header_sum.to_be_bytes());
        out.extend_from_slice(&0x0800_u16.to_be_bytes());
        out.extend_from_slice(&header);
    }
    out.extend_from_slice(&tcp);
    out
}

impl Recorder for PcapRecorder {
    fn opened(&self, session: &Session) -> core::result::Result<(), RecordError> {
        let client = session
            .client()
            .unwrap_or_else(|| SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));
        let server = session
            .server()
            .unwrap_or_else(|| SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)));
        let mut state = self.lock();
        state.flows.insert(
            session.id(),
            Flow {
                client,
                server,
                seq: [0, 0],
            },
        );
        let id = session.id();
        self.send(&mut state, id, Sender::Client, SYN, &[])?;
        // The reply's acknowledgement number counts the client's SYN.
        self.send(&mut state, id, Sender::Server, SYN | ACK, &[])?;
        self.send(&mut state, id, Sender::Client, ACK, &[])
    }

    fn data(
        &self,
        session: &Session,
        sender: Sender,
        data: &[u8],
    ) -> core::result::Result<(), RecordError> {
        let mut state = self.lock();
        for chunk in data.chunks(self.mss) {
            self.send(&mut state, session.id(), sender, PSH | ACK, chunk)?;
        }
        Ok(())
    }

    fn ended(&self, session: &Session, sender: Sender) -> core::result::Result<(), RecordError> {
        let mut state = self.lock();
        self.send(&mut state, session.id(), sender, FIN | ACK, &[])
    }

    fn closed(&self, session: &Session) -> core::result::Result<(), RecordError> {
        self.lock().flows.remove(&session.id());
        let mut shared = self.shared.clone();
        shared
            .flush()
            .map_err(|_| RecordError::new("the capture file cannot be flushed"))
    }
}
