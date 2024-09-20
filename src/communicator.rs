use serde::{Serialize, Deserialize};
use std::io::{self, Result, Write, Read};
use std::net::{TcpStream, SocketAddr};
use std::time::Duration;
use bcs;

// 定义 Communicator trait
pub trait Communicator {
    fn send<T: Serialize>(&mut self, message: &T) -> Result<()>;
    fn receive<T: for<'de> Deserialize<'de>>(&mut self) -> Result<T>;

    fn send_ack(&mut self) -> Result<()>;
    fn receive_ack(&mut self) -> Result<()>;
}

// Tcp 通信实现
pub struct SyncTcpCommunicator {
    stream: TcpStream,
}

impl Communicator for SyncTcpCommunicator {
    fn send<T: Serialize>(&mut self, message: &T) -> io::Result<()> {
        let serialized = bcs::to_bytes(message).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let length = serialized.len();
        if length > MAX_MESSAGE_SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Message size exceeds maximum allowed limit"));
        }

        let length_bytes = (length as u32).to_be_bytes();
        self.stream.write_all(&length_bytes)?;
        self.stream.write_all(&serialized)?;
        Ok(())
    }

    fn receive<T: for<'de> Deserialize<'de>>(&mut self) -> io::Result<T> {
        let mut length_bytes = [0; 4];
        self.stream.read_exact(&mut length_bytes)?;
        let length = u32::from_be_bytes(length_bytes) as usize;

        if length > MAX_MESSAGE_SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Received message size exceeds maximum allowed limit"));
        }

        let mut buffer = vec![0; length];
        self.stream.read_exact(&mut buffer)?;
        let deserialized = bcs::from_bytes(&buffer).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(deserialized)
    }

    fn send_ack(&mut self) -> io::Result<()> {
        self.stream.write_all(b"ACK")?;
        Ok(())
    }

    fn receive_ack(&mut self) -> io::Result<()> {
        let mut ack_buf = [0; 3];
        self.stream.read_exact(&mut ack_buf)?;
        if &ack_buf == b"ACK" {
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid ACK received"))
        }
    }


}


const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;
