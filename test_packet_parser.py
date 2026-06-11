import pytest
from packet_parser import parse_ipv4_header

# Um pacote IPv4 válido em formato hexadecimal (capturado de uma rede real)
# Versão: 4, TTL: 64, Protocolo: 17 (UDP), Origem: 192.168.1.50, Destino: 8.8.8.8
VALID_PACKET_HEX = "450000281c4640004011b82dc0a8013208080808"

def test_valid_packet_parsing():
    # Teste 1: Garante que um pacote perfeitamente estruturado é lido corretamente
    packet_bytes = bytes.fromhex(VALID_PACKET_HEX)
    result = parse_ipv4_header(packet_bytes)
    
    assert result["version"] == 4
    assert result["ttl"] == 64
    assert result["protocol"] == 17
    assert result["source_ip"] == "192.168.1.50"
    assert result["destination_ip"] == "8.8.8.8"

def test_packet_too_short():
    # Teste 2: Garante erro se o pacote vier incompleto (menos de 20 bytes)
    short_packet = bytes.fromhex("450000281c464000")
    with pytest.raises(ValueError, match="Pacote muito curto"):
        parse_ipv4_header(short_packet)

def test_invalid_ip_version():
    # Teste 3: Altera o primeiro byte para simular uma versão inválida (ex: IPv6 '65...')
    # Modificamos o '45' inicial para '65'
    invalid_version_hex = "65" + VALID_PACKET_HEX[2:]
    packet_bytes = bytes.fromhex(invalid_version_hex)
    
    with pytest.raises(ValueError, match="Versão de IP inválida"):
        parse_ipv4_header(packet_bytes)

def test_ttl_expired():
    # Teste 4: Altera o byte do TTL (9º byte / offset 16-18 no hex) para '00'
    # Original: ...4000[40]11... -> Modificado: ...4000[00]11...
    expired_ttl_hex = VALID_PACKET_HEX[:16] + "00" + VALID_PACKET_HEX[18:]
    packet_bytes = bytes.fromhex(expired_ttl_hex)
    
    with pytest.raises(ValueError, match="Pacote descartado: TTL igual a zero"):
        parse_ipv4_header(packet_bytes)

def test_invalid_total_length():
    # Teste 5: Altera o campo Total Length (bytes 2 e 3) para um valor menor que 20 (ex: 0 bytes)
    # Original: 4500[0028]... -> Modificado: 4500[0005]...
    invalid_len_hex = VALID_PACKET_HEX[:4] + "0005" + VALID_PACKET_HEX[8:]
    packet_bytes = bytes.fromhex(invalid_len_hex)
    
    with pytest.raises(ValueError, match="Total Length inválido"):
        parse_ipv4_header(packet_bytes)
