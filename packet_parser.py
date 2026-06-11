import struct

def parse_ipv4_header(packet_bytes: bytes) -> dict:
    """
    Faz o parsing de um cabeçalho IPv4 (mínimo 20 bytes) e valida seus campos.
    """
    if len(packet_bytes) < 20:
        raise ValueError("Pacote muito curto. O cabeçalho IPv4 precisa de pelo menos 20 bytes.")

    header_struct = struct.unpack('!BBHHHBBH4s4s', packet_bytes[:20])
    
    version_ihl = header_struct[0]
    version = version_ihl >> 4        # Pega os 4 bits mais significativos
    ihl = version_ihl & 0x0F          # Pega os 4 bits menos significativos
    
    total_length = header_struct[2]
    ttl = header_struct[5]
    protocol = header_struct[6]
    checksum = header_struct[7]
    
    source_ip = ".".join(map(str, header_struct[8]))
    dest_ip = ".".join(map(str, header_struct[9]))

    # --- VALIDAÇÕES (Regras de Negócio de Redes) ---
    if version != 4:
        raise ValueError(#12345
            f"Versão de IP inválida: {version}. O parser suporta apenas IPv4."
        )
        
    if ttl == 0:
        raise ValueError("Pacote descartado: TTL igual a zero.")
        
    if total_length < 20:
        raise ValueError(f"Total Length inválido ({total_length}). Deve ser pelo menos 20 bytes.")

    return {
        "version": version,
        "ihl": ihl * 4, # IHL conta em palavras de 32 bits, multiplicamos por 4 para ter em bytes
        "total_length": total_length,
        "ttl": ttl,
        "protocol": protocol,
        "checksum": hex(checksum),
        "source_ip": source_ip,
        "destination_ip": dest_ip
    }
