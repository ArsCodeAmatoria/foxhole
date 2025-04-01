use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};
use native_tls::TlsConnector;

pub struct ConnectionConfig {
    pub max_retries: u32,
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub backoff_factor: f64,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            max_retries: 5,
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(30),
            backoff_factor: 2.0,
        }
    }
}

pub struct Connection {
    stream: Option<TcpStream>,
    tls: bool,
    config: ConnectionConfig,
}

impl Connection {
    pub fn new(tls: bool, config: ConnectionConfig) -> Self {
        Self {
            stream: None,
            tls,
            config,
        }
    }

    pub fn connect(&mut self, addr: &str) -> io::Result<()> {
        let mut retries = 0;
        let mut delay = self.config.initial_delay;
        let start_time = Instant::now();

        loop {
            match self.try_connect(addr) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    if retries >= self.config.max_retries {
                        return Err(e);
                    }

                    std::thread::sleep(delay);
                    delay = std::cmp::min(
                        Duration::from_secs_f64(
                            delay.as_secs_f64() * self.config.backoff_factor,
                        ),
                        self.config.max_delay,
                    );
                    retries += 1;
                }
            }
        }
    }

    fn try_connect(&mut self, addr: &str) -> io::Result<()> {
        let stream = TcpStream::connect(addr)?;
        
        if self.tls {
            let connector = TlsConnector::new()?;
            let stream = connector.connect("", stream)?;
            self.stream = Some(stream);
        } else {
            self.stream = Some(stream);
        }

        Ok(())
    }

    pub fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match &mut self.stream {
            Some(stream) => stream.read(buffer),
            None => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "Not connected to remote host",
            )),
        }
    }

    pub fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match &mut self.stream {
            Some(stream) => stream.write(buffer),
            None => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "Not connected to remote host",
            )),
        }
    }

    pub fn flush(&mut self) -> io::Result<()> {
        match &mut self.stream {
            Some(stream) => stream.flush(),
            None => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "Not connected to remote host",
            )),
        }
    }
} 