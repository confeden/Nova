//! A WebSocket over a byte stream, using `nova_tgrelay::wsframe` for the framing.
//!
//! The stream half of layer 9. `RawWebSocket` in the Python owns both; keeping
//! them apart is what let every frame the relay can receive be constructed as a
//! byte slice in a test, and what leaves this file with nothing in it but socket
//! bookkeeping.
//!
//! The handshake is **not** here, and that is deliberate. It happens in exactly
//! one place, `transparent_relay._connect_websocket_once`, so that it goes out
//! through `transport.open_tls_stream` and therefore through the terminator. The
//! Python module used to carry a second `connect` with its own
//! `ssl.create_default_context()`; its only caller was dead code, but the
//! fingerprint it would have emitted is `t13d181100`, which identifies Nova and
//! nothing else. Do not add one here either.

use nova_tgrelay::wsframe::{build_frame, FrameError, Incoming, MaskSource, MessageReader, Opcode, MAX_MESSAGE};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

/// The mask source a real client uses.
///
/// `getrandom` rather than a seeded generator: the mask exists to stop a peer
/// predicting the bytes on the wire, and it is already in this workspace's
/// dependency tree, so naming it here adds nothing to build.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsMask;

impl MaskSource for OsMask {
    fn next_mask(&mut self) -> [u8; 4] {
        let mut key = [0u8; 4];
        getrandom::fill(&mut key).expect("the OS random source is unavailable");
        key
    }
}

/// What ended a `recv`.
#[derive(Debug)]
pub enum WsError {
    /// The frame on the wire could not be read. Every variant ends the tunnel.
    Frame(FrameError),
    Io(io::Error),
}

impl From<FrameError> for WsError {
    fn from(e: FrameError) -> Self {
        Self::Frame(e)
    }
}

impl From<io::Error> for WsError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl std::fmt::Display for WsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Frame(e) => write!(f, "websocket frame: {e:?}"),
            Self::Io(e) => write!(f, "websocket io: {e}"),
        }
    }
}

impl std::error::Error for WsError {}

/// What the peer said. A ping is handed up rather than answered here, because
/// the reader half owns no writer — and because "somebody must answer this"
/// belongs where it can be seen, not buried in a loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsEvent {
    Message(Vec<u8>),
    /// Answer with [`WsWriter::pong`] carrying these bytes.
    Ping(Vec<u8>),
    /// The peer closed, with its code if it sent one. Echo it with
    /// [`WsWriter::close_echo`] and stop.
    Closed(Option<u16>),
}

/// The reading half.
pub struct WsReader<R> {
    stream: R,
    reader: MessageReader,
    read_buf: Vec<u8>,
    closed: bool,
}

impl<R: AsyncRead + Unpin> WsReader<R> {
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// The next thing the peer said, or `None` once it has stopped speaking.
    pub async fn next_event(&mut self) -> Result<Option<WsEvent>, WsError> {
        loop {
            if self.closed {
                return Ok(None);
            }
            match self.reader.next_incoming()? {
                Incoming::Message(payload) => return Ok(Some(WsEvent::Message(payload))),
                Incoming::Ping(payload) => return Ok(Some(WsEvent::Ping(payload))),
                Incoming::Pong => continue,
                Incoming::Close(code) => {
                    self.closed = true;
                    return Ok(Some(WsEvent::Closed(code)));
                }
                Incoming::NeedMore => {}
            }
            let read = self.stream.read(&mut self.read_buf).await?;
            if read == 0 {
                // EOF with no close frame. Not an error: a peer that vanishes
                // mid-tunnel is the ordinary case on this path, and calling it
                // one would fill the log with noise for something normal.
                self.closed = true;
                return Ok(None);
            }
            let chunk = self.read_buf[..read].to_vec();
            self.reader.feed(&chunk);
        }
    }
}

/// The writing half. Owns the mask source, because only outgoing frames are
/// masked.
pub struct WsWriter<W, M = OsMask> {
    stream: W,
    mask: M,
    closed: bool,
}

impl<W: AsyncWrite + Unpin, M: MaskSource> WsWriter<W, M> {
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    pub async fn send(&mut self, payload: &[u8]) -> Result<(), WsError> {
        self.send_batch(std::slice::from_ref(&payload)).await
    }

    /// Send several messages with **one** flush.
    ///
    /// The relay splits a client read into whole MTProto messages and sends them
    /// together; flushing between them would put each on its own packet and turn
    /// one round trip into several.
    pub async fn send_batch(&mut self, payloads: &[&[u8]]) -> Result<(), WsError> {
        if self.closed {
            return Err(WsError::Io(io::Error::new(io::ErrorKind::NotConnected, "WebSocket closed")));
        }
        for payload in payloads {
            let key = self.mask.next_mask();
            let frame = build_frame(Opcode::Binary, payload, Some(key));
            self.stream.write_all(&frame).await?;
        }
        self.stream.flush().await?;
        Ok(())
    }

    pub async fn pong(&mut self, payload: &[u8]) -> Result<(), WsError> {
        self.control(Opcode::Pong, payload).await
    }

    /// Echo a close code back, best effort: the peer that just closed may
    /// already be gone.
    pub async fn close_echo(&mut self, code: Option<u16>) {
        self.closed = true;
        let echo = code.map(u16::to_be_bytes).unwrap_or_default();
        let body: &[u8] = if code.is_some() { &echo } else { &[] };
        let _ = self.control(Opcode::Close, body).await;
    }

    /// Say goodbye and stop. Idempotent.
    pub async fn close(&mut self) -> Result<(), WsError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let _ = self.control(Opcode::Close, &[]).await;
        let _ = self.stream.shutdown().await;
        Ok(())
    }

    async fn control(&mut self, opcode: Opcode, payload: &[u8]) -> Result<(), WsError> {
        let key = self.mask.next_mask();
        let frame = build_frame(opcode, payload, Some(key));
        self.stream.write_all(&frame).await?;
        self.stream.flush().await?;
        Ok(())
    }
}

/// A framed WebSocket over an already-connected, already-upgraded stream.
///
/// Holds both halves and can hand them out with [`Self::split`], which the
/// bridge needs: one direction reads while the other writes, and a single `&mut`
/// cannot be in two futures at once.
pub struct WsConnection<S, M = OsMask> {
    reader: WsReader<ReadHalf<S>>,
    writer: WsWriter<WriteHalf<S>, M>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> WsConnection<S, OsMask> {
    pub fn new(stream: S) -> Self {
        Self::with_mask_source(stream, OsMask)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin, M: MaskSource> WsConnection<S, M> {
    pub fn with_mask_source(stream: S, mask: M) -> Self {
        let (read, write) = tokio::io::split(stream);
        Self {
            reader: WsReader {
                stream: read,
                reader: MessageReader::new(MAX_MESSAGE),
                read_buf: vec![0u8; 64 * 1024],
                closed: false,
            },
            writer: WsWriter { stream: write, mask, closed: false },
        }
    }

    /// Hand out the two halves so the two directions can run at once.
    pub fn split(self) -> (WsReader<ReadHalf<S>>, WsWriter<WriteHalf<S>, M>) {
        (self.reader, self.writer)
    }

    pub fn is_closed(&self) -> bool {
        self.reader.is_closed() || self.writer.is_closed()
    }

    pub async fn send(&mut self, payload: &[u8]) -> Result<(), WsError> {
        self.writer.send(payload).await
    }

    pub async fn send_batch(&mut self, payloads: &[&[u8]]) -> Result<(), WsError> {
        self.writer.send_batch(payloads).await
    }

    /// The next data message, answering pings on the way.
    ///
    /// The convenience form, for callers with one direction to worry about. The
    /// bridge uses [`Self::split`] instead.
    pub async fn recv(&mut self) -> Result<Option<Vec<u8>>, WsError> {
        loop {
            match self.reader.next_event().await? {
                None => return Ok(None),
                Some(WsEvent::Message(payload)) => return Ok(Some(payload)),
                Some(WsEvent::Ping(payload)) => self.writer.pong(&payload).await?,
                Some(WsEvent::Closed(code)) => {
                    self.writer.close_echo(code).await;
                    return Ok(None);
                }
            }
        }
    }

    pub async fn close(&mut self) -> Result<(), WsError> {
        self.writer.close().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nova_tgrelay::wsframe::{parse_header, FixedMask};
    use tokio::io::duplex;

    const KEY: [u8; 4] = [1, 2, 3, 4];

    /// Build what a server would put on the wire: unmasked, FIN as asked.
    fn server_frame(opcode: Opcode, payload: &[u8], fin: bool) -> Vec<u8> {
        let mut f = build_frame(opcode, payload, None);
        if !fin {
            f[0] &= 0x7F;
        }
        f
    }

    #[tokio::test]
    async fn a_message_is_sent_masked_and_whole() {
        let (mine, mut theirs) = duplex(4096);
        let mut ws = WsConnection::with_mask_source(mine, FixedMask(KEY));
        ws.send(b"mtproto").await.expect("send");

        let mut wire = vec![0u8; 13];
        theirs.read_exact(&mut wire).await.expect("read");
        let header = parse_header(&wire).expect("valid").expect("complete");
        assert!(header.fin);
        assert_eq!(header.opcode, Opcode::Binary);
        assert_eq!(header.mask, Some(KEY), "a client must mask every frame");
        let mut body = wire[header.header_len..].to_vec();
        nova_tgrelay::wsframe::apply_mask(&mut body, KEY);
        assert_eq!(body, b"mtproto");
    }

    #[tokio::test]
    async fn a_batch_goes_out_as_separate_frames_in_order() {
        let (mine, mut theirs) = duplex(4096);
        let mut ws = WsConnection::with_mask_source(mine, FixedMask(KEY));
        ws.send_batch(&[b"one".as_slice(), b"two".as_slice()]).await.expect("send");

        let mut wire = vec![0u8; 18];
        theirs.read_exact(&mut wire).await.expect("read");
        let first = parse_header(&wire).expect("valid").expect("complete");
        assert_eq!(first.payload_len, 3);
        let second_at = first.frame_len() as usize;
        let second = parse_header(&wire[second_at..]).expect("valid").expect("complete");
        assert_eq!(second.payload_len, 3);
        let mut body = wire[second_at + second.header_len..].to_vec();
        nova_tgrelay::wsframe::apply_mask(&mut body, KEY);
        assert_eq!(body, b"two");
    }

    #[tokio::test]
    async fn several_frames_arriving_in_one_read_are_all_delivered() {
        let (mine, mut theirs) = duplex(4096);
        let mut wire = server_frame(Opcode::Binary, b"one", true);
        wire.extend(server_frame(Opcode::Binary, b"two", true));
        theirs.write_all(&wire).await.expect("write");

        let mut ws = WsConnection::with_mask_source(mine, FixedMask(KEY));
        assert_eq!(ws.recv().await.expect("recv"), Some(b"one".to_vec()));
        assert_eq!(ws.recv().await.expect("recv"), Some(b"two".to_vec()));
    }

    #[tokio::test]
    async fn a_message_split_across_reads_is_reassembled() {
        let (mine, mut theirs) = duplex(4096);
        let frame = server_frame(Opcode::Binary, b"telegram", true);
        theirs.write_all(&frame[..3]).await.expect("write");
        let mut ws = WsConnection::with_mask_source(mine, FixedMask(KEY));
        let recv = tokio::spawn(async move {
            let got = ws.recv().await.expect("recv");
            (got, ws)
        });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        theirs.write_all(&frame[3..]).await.expect("write");
        let (got, _ws) = recv.await.expect("join");
        assert_eq!(got, Some(b"telegram".to_vec()));
    }

    #[tokio::test]
    async fn a_ping_is_answered_without_troubling_the_caller() {
        let (mine, mut theirs) = duplex(4096);
        let mut wire = server_frame(Opcode::Ping, b"hi", true);
        wire.extend(server_frame(Opcode::Binary, b"after", true));
        theirs.write_all(&wire).await.expect("write");

        let mut ws = WsConnection::with_mask_source(mine, FixedMask(KEY));
        assert_eq!(ws.recv().await.expect("recv"), Some(b"after".to_vec()));

        // The pong went out before the message came back.
        let mut pong = vec![0u8; 8];
        theirs.read_exact(&mut pong).await.expect("read pong");
        let header = parse_header(&pong).expect("valid").expect("complete");
        assert_eq!(header.opcode, Opcode::Pong);
        let mut body = pong[header.header_len..].to_vec();
        nova_tgrelay::wsframe::apply_mask(&mut body, KEY);
        assert_eq!(body, b"hi");
    }

    #[tokio::test]
    async fn a_close_frame_ends_the_connection_and_is_echoed() {
        let (mine, mut theirs) = duplex(4096);
        theirs.write_all(&server_frame(Opcode::Close, &1000u16.to_be_bytes(), true)).await.expect("write");

        let mut ws = WsConnection::with_mask_source(mine, FixedMask(KEY));
        assert_eq!(ws.recv().await.expect("recv"), None);
        assert!(ws.is_closed());
        assert_eq!(ws.recv().await.expect("recv"), None, "still closed, still quiet");

        let mut echo = vec![0u8; 8];
        theirs.read_exact(&mut echo).await.expect("read echo");
        let header = parse_header(&echo).expect("valid").expect("complete");
        assert_eq!(header.opcode, Opcode::Close);
        let mut body = echo[header.header_len..].to_vec();
        nova_tgrelay::wsframe::apply_mask(&mut body, KEY);
        assert_eq!(body, 1000u16.to_be_bytes());
    }

    #[tokio::test]
    async fn a_peer_that_vanishes_is_a_close_not_an_error() {
        // No close frame, just EOF. The ordinary case on this path, and treating
        // it as an error would fill the log with noise for something normal.
        let (mine, theirs) = duplex(4096);
        drop(theirs);
        let mut ws = WsConnection::with_mask_source(mine, FixedMask(KEY));
        assert_eq!(ws.recv().await.expect("recv"), None);
        assert!(ws.is_closed());
    }

    #[tokio::test]
    async fn a_deflated_frame_is_refused_rather_than_forwarded() {
        let (mine, mut theirs) = duplex(4096);
        let mut frame = server_frame(Opcode::Binary, b"compressed", true);
        frame[0] |= 0x40; // RSV1
        theirs.write_all(&frame).await.expect("write");

        let mut ws = WsConnection::with_mask_source(mine, FixedMask(KEY));
        let error = ws.recv().await.expect_err("must fail");
        assert!(matches!(error, WsError::Frame(FrameError::ReservedBitsSet(0x40))), "{error}");
    }

    #[tokio::test]
    async fn sending_on_a_closed_connection_is_refused_rather_than_silent() {
        let (mine, _theirs) = duplex(4096);
        let mut ws = WsConnection::with_mask_source(mine, FixedMask(KEY));
        ws.close().await.expect("close");
        assert!(ws.send(b"too late").await.is_err());
    }

    #[tokio::test]
    async fn closing_twice_is_harmless() {
        let (mine, _theirs) = duplex(4096);
        let mut ws = WsConnection::with_mask_source(mine, FixedMask(KEY));
        ws.close().await.expect("close");
        ws.close().await.expect("close again");
    }
}
