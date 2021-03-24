
use 
{
    std::io::Cursor,
    std::io::Read,
    std::io::Write,
    std::io::Error,
    byteorder::ReadBytesExt,
    byteorder::BigEndian,
    tokio::net::TcpListener,
    tokio::net::TcpStream,
    tokio::io::{AsyncReadExt, AsyncWriteExt},
};

struct RecordOutput<'a>
{
    content_type:u8,
    protocol_version:u16,
    dns_hostname:&'a mut String
} 

#[tokio::main]
pub async fn main() 
{
    let listener = TcpListener::bind("[::]:443").await.unwrap();

    loop
    {
        let stream = listener.accept().await;

        match stream {
            Ok(mut stream) => {
                //let mut stream = stream;
                println!("new client!");
                let mut is_data = true;
                
                let n = handle_record_packet(stream.0).await;

                match n
                {
                    Ok(_) => {},
                    Err(e) => println!("Connection lost {}",e),
                }
            }
            Err(e) => { /* connection failed */ }
        }
    }
}

async fn handle_record_packet(mut stream: tokio::net::TcpStream) -> Result<usize,tokio::io::Error>
{
    use byteorder::WriteBytesExt;
    let mut buffer = [0;5];
    let n = stream.read(&mut buffer).await?;

    let mut record_output = RecordOutput {dns_hostname:&mut String::new(),content_type:0,protocol_version:0};

    let mut rdr = Cursor::new(buffer);

    record_output.content_type = ReadBytesExt::read_u8(&mut rdr)?;
    record_output.protocol_version = ReadBytesExt::read_u16::<BigEndian>(&mut rdr)?;
    
    let packet_length = ReadBytesExt::read_u16::<BigEndian>(&mut rdr)?;

    //println!("{} {:x?} {:x?} {}",n,content_type,protocol_version,length);

    let mut buffer = vec![0u8;packet_length as usize];
    let n = stream.read(&mut buffer).await?;

    println!("done read {}",n);

    let mut rdr = Cursor::new(&buffer);
    let content_type = ReadBytesExt::read_u8(&mut rdr)?;

    let length = ReadBytesExt::read_u24::<BigEndian>(&mut rdr)?;

    println!("record: type:{} length:{}",content_type,length);
    
    match content_type {
        1 => handle_client_hello(&mut record_output,&buffer[4..]),
        _ => (),
    }

    if !record_output.dns_hostname.is_empty()
    {
        let mut dns_hostname:String = String::from("geekylou.me.uk:443");
        //record_output.dns_hostname.clone() + ":443";

        let mut outbound_connection = Box::new(TcpStream::connect(dns_hostname).await.unwrap());
        let mut stream_boxed = Box::new(stream);

        let mut v:Vec<u8> = Vec::new();
        let mut writer = Cursor::new(&mut v);

        WriteBytesExt::write_u8(&mut writer,record_output.content_type)?;
        WriteBytesExt::write_u16::<BigEndian>(&mut writer,record_output.protocol_version)?;
        WriteBytesExt::write_u16::<BigEndian>(&mut writer,buffer.len() as u16)?;

        outbound_connection.write(&v).await?;
        outbound_connection.write(&buffer).await?;

        let (mut outbound_rd, mut outbound_wr) = tokio::io::split(outbound_connection);
        let (mut stream_rd, mut stream_wr) = tokio::io::split(stream_boxed);

        tokio::spawn(async move {
            forward(&mut outbound_rd,&mut stream_wr).await;

        });
        forward(&mut stream_rd,&mut outbound_wr).await;
    }
    
    
    return Ok(n);
}

async fn forward(stream_in:&mut tokio::io::ReadHalf<Box<TcpStream>>,stream_out:&mut tokio::io::WriteHalf<Box<TcpStream>>) -> Result<(),std::io::Error>
{
    loop
    {
        let mut buffer_in_client = [0;5];

        let n = stream_in.read(&mut buffer_in_client).await?;

        let mut rdr = Cursor::new(buffer_in_client);
        
        print!("rt {:x?} ",ReadBytesExt::read_u8(&mut rdr)?); // Skip record type.
        print!("pt {:x?} ",ReadBytesExt::read_u16::<BigEndian>(&mut rdr)?); // Skip protocol version.
        
        let buffer_in_client_payload_length = ReadBytesExt::read_u16::<BigEndian>(&mut rdr)?;
        let mut buffer_in_client_payload = vec![0u8;buffer_in_client_payload_length as usize];
        
        stream_in.read_exact(&mut buffer_in_client_payload).await?;

        stream_out.write(&buffer_in_client).await?;
        stream_out.write(&buffer_in_client_payload).await?;

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

    let protocol_version = ReadBytesExt::read_u16::<BigEndian>(&mut rdr).unwrap();
    std::io::Read::read(&mut rdr,&mut random).unwrap();

    let legacy_session_id_length = ReadBytesExt::read_u8(&mut rdr).unwrap();
    if legacy_session_id_length > 0
    {
        let mut legacy_session_id = vec![0u8;legacy_session_id_length as usize];
        std::io::Read::read(&mut rdr,&mut legacy_session_id).unwrap();
    }

    let cipher_suite_length = ReadBytesExt::read_u16::<BigEndian>(&mut rdr).unwrap();
    if cipher_suite_length > 0
    {
        let mut cipher_suite = vec![0u8;cipher_suite_length as usize];
        std::io::Read::read(&mut rdr,&mut cipher_suite).unwrap();
    }

    let legacy_compression_length = ReadBytesExt::read_u8(&mut rdr).unwrap();
    if legacy_compression_length > 0
    {
        let mut legacy_compression = vec![0u8;legacy_compression_length as usize];
        std::io::Read::read(&mut rdr,&mut legacy_compression).unwrap();
    }

    println!("protocol version: {:x?} session_id_length:{} cipher_suit_lengh:{} legacy_compression_length:{}",protocol_version,legacy_session_id_length,cipher_suite_length,legacy_compression_length);

    let extensions_length = ReadBytesExt::read_u16::<BigEndian>(&mut rdr).unwrap();
    if extensions_length > 0
    {
        while rdr.position() != buffer.len() as u64
        {   
            println!("position {} ",rdr.position());
            let extension_type = ReadBytesExt::read_u16::<BigEndian>(&mut rdr).unwrap();
            let extension_type_length = ReadBytesExt::read_u16::<BigEndian>(&mut rdr).unwrap();

            println!("Extension: {:x?} length {}",extension_type,extension_type_length);

            if extension_type_length>0
            {
                let mut extension = vec![0u8;extension_type_length as usize];
                std::io::Read::read(&mut rdr,&mut extension).unwrap();

                if extension_type == 0x00
                {
                    let mut rdr = Cursor::new(&extension);
                    let _sni_length = ReadBytesExt::read_u16::<BigEndian>(&mut rdr); // Unused but this advances the ptr.

                    let sni_list_entry_type = ReadBytesExt::read_u8(&mut rdr).unwrap();

                    if sni_list_entry_type == 0
                    {
                        // DNS hostname type read hostname.
                        let dns_length = ReadBytesExt::read_u16::<BigEndian>(&mut rdr).unwrap();
                        let mut dns_hostname = vec![0u8;dns_length as usize];
                        
                        std::io::Read::read(&mut rdr,&mut dns_hostname).unwrap();

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

