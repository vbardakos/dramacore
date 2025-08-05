use std::{ops::Range, usize};

use chacha20poly1305::{
    aead::{rand_core::RngCore, Aead, OsRng},
    ChaCha20Poly1305, KeyInit, Nonce,
};

use crate::codec::{err, key, magic, CodecExt};

type PacketSequence = u32;

#[derive(Debug, Clone, PartialEq)]
pub struct PacketVersion(u16);

#[derive(Debug, Clone, PartialEq)]
pub struct Packet {
    seq: PacketSequence,
    version: PacketVersion,
    header: Vec<u8>,
    body: Vec<u8>,
}

impl<'a> CodecExt<'a> for Packet {
    type Error = err::CodecError;

    fn serialize(self) -> Result<Vec<u8>, Self::Error> {
        let mut nonce_bytes = [0u8; 12];

        let ciphertext = {
            let cipher = ChaCha20Poly1305::new_from_slice(&key::get()?)
                .map_err(|_| err::CodecError::Encryption)?;

            let mut bufr = Vec::new();
            bufr.extend_from_slice(&self.version.0.to_be_bytes());
            bufr.extend_from_slice(&(self.header.len() as u16).to_be_bytes());
            bufr.extend_from_slice(&self.header);
            bufr.extend_from_slice(&self.body);

            OsRng.fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::from_slice(&nonce_bytes);
            cipher
                .encrypt(nonce, bufr.as_ref())
                .map_err(|_| err::CodecError::Encryption)?
        };

        let mut bufr = Vec::new();
        bufr.extend_from_slice(magic::MAGIC);
        bufr.extend_from_slice(&self.seq.to_be_bytes());
        bufr.extend_from_slice(&(ciphertext.len() as u32 + 12).to_be_bytes());
        bufr.extend_from_slice(&nonce_bytes);
        bufr.extend_from_slice(&ciphertext);

        Ok(bufr)
    }

    fn deserialize(ser: &'a [u8]) -> Result<Self, Self::Error> {
        const MINSIZE: usize = 22;

        if ser.len() < MINSIZE {
            return Err(err::CodecError::Incomplete);
        }
        let (magic, cursor) = ser.split_at(2);

        if magic != magic::MAGIC {
            return Err(err::CodecError::InvalidMagic);
        }

        let seq = c32(cursor, 0..4);
        let len = c32(cursor, 4..8) as usize;

        if len != cursor[8..].len() {
            if len < cursor[8..].len() {
                return Err(err::CodecError::Incomplete);
            }
            return Err(err::CodecError::Corrupted {
                el: "Packet".into(),
                seq: seq as usize,
            });
        };

        let payload = {
            let cipher = ChaCha20Poly1305::new_from_slice(&key::get()?)
                .map_err(|_| err::CodecError::Decryption)?;
            let nonce = Nonce::from_slice(&cursor[8..20]);
            cipher
                .decrypt(nonce, &cursor[20..])
                .map_err(|_| err::CodecError::Corrupted {
                    el: "Packet".into(),
                    seq: seq as usize,
                })?
        };

        let version = PacketVersion(c16(&payload, 0..2));
        let headoff = c16(&payload, 2..4) as usize + 4;

        Ok(Packet {
            seq,
            version,
            header: payload[4..headoff].to_vec(),
            body: payload[headoff..].to_vec(),
        })
    }
}

fn c16(b: &[u8], idx: Range<usize>) -> u16 {
    u16::from_be_bytes(b[idx].try_into().unwrap())
}

fn c32(b: &[u8], idx: Range<usize>) -> u32 {
    u32::from_be_bytes(b[idx].try_into().unwrap())
}
