
use 
{
    std::io::Cursor,
    std::net::TcpListener,
    std::net::TcpStream,
    std::io::Read,
    std::io::Write,
    std::io::Error,
    byteorder::ReadBytesExt,
    byteorder::BigEndian,
};

struct RecordOutput<'a>
{
    content_type:u8,
    protocol_version:u16,
    dns_hostname:&'a mut String
} 

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

fn handle_record_contents(mut record_output :&mut RecordOutput,mut stream: &std::net::TcpStream, packet_length: usize) -> Result<usize,std::io::Error>
{
    use byteorder::ReadBytesExt;
    use byteorder::WriteBytesExt;
    use byteorder::BigEndian;
    use std::net::TcpStream;
    use pretty_hex::*;
    use std::thread;

    let mut buffer = vec![0u8;packet_length];
    let n = stream.read(&mut buffer)?;

    println!("done read {}",n);

    let mut rdr = Cursor::new(&buffer);
    let content_type = rdr.read_u8()?;

    let length = rdr.read_u24::<BigEndian>()?;

    println!("record: type:{} length:{}",content_type,length);
    
    match content_type {
        1 => handle_client_hello(&mut record_output,&buffer[4..]),
        _ => (),
    }

    if !record_output.dns_hostname.is_empty()
    {
        let mut dns_hostname:String = String::from("geekylou.me.uk:443");
        //record_output.dns_hostname.clone() + ":443";

        let mut outbound_connection = TcpStream::connect(dns_hostname).unwrap();
        
        let mut v:Vec<u8> = Vec::new();
        let mut writer = Cursor::new(&mut v);

        writer.write_u8(record_output.content_type)?;
        writer.write_u16::<BigEndian>(record_output.protocol_version)?;
        writer.write_u16::<BigEndian>(buffer.len() as u16)?;

        outbound_connection.write(&v)?;
        outbound_connection.write(&buffer)?;

        let mut x = stream.try_clone().unwrap();
        let mut y = outbound_connection.try_clone().unwrap();
        
        let th = thread::spawn(move || {
            
            forward(&mut x,&mut y).unwrap();
        });
        loop
        {
            let mut buffer_in_client = [0;5];

            let n =outbound_connection.read(&mut buffer_in_client)?;

            let mut rdr = Cursor::new(buffer_in_client);
            
            print!("rt {:x?} ",rdr.read_u8()?); // Skip record type.
            print!("pt {:x?} ",rdr.read_u16::<BigEndian>()?); // Skip protocol version.
            
            let buffer_in_client_payload_length = rdr.read_u16::<BigEndian>()?;
            let mut buffer_in_client_payload = vec![0u8;buffer_in_client_payload_length as usize];
            
            outbound_connection.read_exact(&mut buffer_in_client_payload)?;

            stream.write(&buffer_in_client)?;
            stream.write(&buffer_in_client_payload)?;

            println!("read {}",buffer_in_client_payload_length);
        }

        th.join().unwrap();
    }
    
    
    return Ok(n);
}

fn forward(stream_in:&mut TcpStream,stream_out:&mut TcpStream) -> Result<(),std::io::Error>
{
    loop
    {
        let mut buffer_in_client = [0;5];

        let n = stream_in.read(&mut buffer_in_client)?;

        let mut rdr = Cursor::new(buffer_in_client);
        
        print!("rt {:x?} ",rdr.read_u8()?); // Skip record type.
        print!("pt {:x?} ",rdr.read_u16::<BigEndian>()?); // Skip protocol version.
        
        let buffer_in_client_payload_length = rdr.read_u16::<BigEndian>()?;
        let mut buffer_in_client_payload = vec![0u8;buffer_in_client_payload_length as usize];
        
        stream_in.read_exact(&mut buffer_in_client_payload)?;

        stream_out.write(&buffer_in_client)?;
        stream_out.write(&buffer_in_client_payload)?;

        println!("read {}",buffer_in_client_payload_length);
    }
}

fn handle_client_hello(record_output :&mut RecordOutput,buffer: &[u8])
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

            if extension_type_length>0
            {
                let mut extension = vec![0u8;extension_type_length as usize];
                rdr.read(&mut extension).unwrap();

                if extension_type == 0x00
                {
                    let mut rdr = Cursor::new(&extension);
                    let _sni_length = rdr.read_u16::<BigEndian>(); // Unused but this advances the ptr.

                    let sni_list_entry_type = rdr.read_u8().unwrap();

                    if sni_list_entry_type == 0
                    {
                        // DNS hostname type read hostname.
                        let dns_length = rdr.read_u16::<BigEndian>().unwrap();
                        let mut dns_hostname = vec![0u8;dns_length as usize];
                        
                        rdr.read(&mut dns_hostname).unwrap();

                        let hostname_str = String::from_utf8(dns_hostname).unwrap();
                        println!("SNI hostname found: {}",hostname_str);
                        record_output.dns_hostname.push_str(&hostname_str);
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
    let n = stream.read(&mut buffer)?;

    let mut record_output = RecordOutput {dns_hostname:&mut String::new(),content_type:0,protocol_version:0};

    let mut rdr = Cursor::new(buffer);

    record_output.content_type = rdr.read_u8()?;
    record_output.protocol_version = rdr.read_u16::<BigEndian>()?;
    
    let length = rdr.read_u16::<BigEndian>()?;

    //println!("{} {:x?} {:x?} {}",n,content_type,protocol_version,length);

    let ret = handle_record_contents(&mut record_output, &mut stream,length as usize);
    
    return ret;
}
