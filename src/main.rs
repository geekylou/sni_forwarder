
use 
{
    std::io::Cursor,
    std::net::TcpListener,
    std::io::Read,
    std::io::Error,
};

fn main() 
{
    let listener = TcpListener::bind("[::]:443").unwrap();

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                //let mut stream = stream;
                println!("new client!");
                let mut is_data = true;
                while is_data
                {                    
                    let n = handle_record_packet(&mut stream);
                    match n
                    {
                        Err(n) => {is_data  = false; println!("Error reading socket:{}",n)},
                        Ok(n) => if n == 0 {is_data = false},
                    }
                }
            }
            Err(e) => { /* connection failed */ }
        }
    }
}

fn handle_record_contents(mut stream: &std::net::TcpStream, packet_length: usize) -> Result<usize,std::io::Error>
{
    use byteorder::ReadBytesExt;
    use byteorder::BigEndian;

    let mut buffer = vec![0u8;packet_length];
    let n = stream.read(&mut buffer)?;

    println!("done read {}",n);

    let mut rdr = Cursor::new(&buffer);
    let content_type = rdr.read_u8()?;

    let length = rdr.read_u24::<BigEndian>()?;

    println!("record: type:{} length:{}",content_type,length);
    
    match content_type {
        1 => handle_client_hello(&buffer[4..]),
        _ => (),
    }
    return Ok(n);
}

fn handle_client_hello(buffer: &[u8])
{
    use byteorder::ReadBytesExt;
    use byteorder::BigEndian;
    use pretty_hex::*;
    
    let mut rdr = Cursor::new(buffer);
    let mut random = [0;32];

    let protocol_version = rdr.read_u16::<BigEndian>().unwrap();
    rdr.read(&mut random).unwrap();

    let legacy_session_id_length = rdr.read_u8().unwrap();
    if legacy_session_id_length > 0
    {
        let mut legacy_session_id = vec![0u8;legacy_session_id_length as usize];
        rdr.read(&mut legacy_session_id).unwrap();
    }

    let cipher_suite_length = rdr.read_u16::<BigEndian>().unwrap();
    if cipher_suite_length > 0
    {
        let mut cipher_suite = vec![0u8;cipher_suite_length as usize];
        rdr.read(&mut cipher_suite).unwrap();
    }

    let legacy_compression_length = rdr.read_u8().unwrap();
    if legacy_compression_length > 0
    {
        let mut legacy_compression = vec![0u8;legacy_compression_length as usize];
        rdr.read(&mut legacy_compression).unwrap();
    }

    println!("protocol version: {:x?} session_id_length:{} cipher_suit_lengh:{} legacy_compression_length:{}",protocol_version,legacy_session_id_length,cipher_suite_length,legacy_compression_length);

    let extensions_length = rdr.read_u16::<BigEndian>().unwrap();
    if extensions_length > 0
    {
        while rdr.position() != buffer.len() as u64
        {   
            println!("position {} ",rdr.position());
            let extension_type = rdr.read_u16::<BigEndian>().unwrap();
            let extension_type_length = rdr.read_u16::<BigEndian>().unwrap();

            println!("Extension: {:x?} length {}",extension_type,extension_type_length);

            if (extension_type_length>0)
            {
                let mut extension = vec![0u8;extension_type_length as usize];
                rdr.read(&mut extension).unwrap();

                if extension_type == 0x00
                {
                    let mut rdr = Cursor::new(&extension);
                    let sni_length = rdr.read_u16::<BigEndian>();

                    let sni_list_entry_type = rdr.read_u8().unwrap();

                    if sni_list_entry_type == 0
                    {
                        // DNS hostname type read hostname.
                        let dns_length = rdr.read_u16::<BigEndian>().unwrap();
                        let mut dns_hostname = vec![0u8;dns_length as usize];
                        
                        rdr.read(&mut dns_hostname).unwrap();

                        let hostname_str = String::from_utf8(dns_hostname).unwrap();
                        println!("SNI hostname found: {}",hostname_str);
                    }
                }
                println!("{:?}", extension.hex_dump());
            }
        }
    }
}

fn handle_record_packet(mut stream: &std::net::TcpStream) -> Result<usize,std::io::Error>
{
    use byteorder::ReadBytesExt;
    use byteorder::BigEndian;

    let mut buffer = [0;5];
    let mut n = stream.read(&mut buffer)?;

    let mut rdr = Cursor::new(buffer);

    let content_type = rdr.read_u8()?;
    let protocol_version = rdr.read_u16::<BigEndian>()?;
    let length = rdr.read_u16::<BigEndian>()?;

    println!("{} {:x?} {:x?} {}",n,content_type,protocol_version,length);

    return handle_record_contents(&mut stream,length as usize);
}