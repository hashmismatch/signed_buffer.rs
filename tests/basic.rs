extern crate signed_buffer;

use signed_buffer::*;

#[test]
fn test_basic() {
    let header = [31, 63, 127];
    let footer = [127, 63, 31];
    let payload = b"Hello world!";

    let s = SignedBuffer::new_sip24(BufferSize::Dynamic { max_bytes: 8192 }, &header, &footer).unwrap();
    let signed = s.sign(&payload[..]).unwrap().assemble();

    assert_eq!(s.buffer_len(payload.len()), 31);
    assert_eq!(signed.len(), 31);

    let (read_bytes, decoded) = s.decode(&signed).unwrap();
    assert_eq!(read_bytes, 31);
    assert_eq!(decoded.get_payload_from_buffer(&signed), &payload[..]);

    
    {
        let mut signed = signed.clone();
        signed[25] = 'F' as u8;
        assert_eq!(Err(RetrievalError::InvalidHash), s.decode(&signed));
    }

    {
        let mut buffer = [0; 128];
        let l = signed.len();

        &mut buffer[0..l].copy_from_slice(&signed);
        &mut buffer[64..64+l].copy_from_slice(&signed);

        assert_eq!(31, buffer[0]);
        assert_eq!(31, buffer[64]);
        
        let detected = s.decode_all(&buffer[..]);
        assert_eq!(detected.len(), 2);

        let ref d = detected[0];
        assert_eq!(0..31, d.entire_buffer);        

        let ref d = detected[1];
        assert_eq!(64..95, d.entire_buffer);

        for d in &detected {
            assert_eq!(d.get_payload_from_buffer(&buffer[..]), &payload[..]);
        }
    }
}
