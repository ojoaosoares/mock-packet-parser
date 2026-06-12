# main.py
import sys
from packet_parser import parse_ipv4_header

def main():
    print("--- Mock IPv4 Packet Parser CLI ---")
    
    # Se o usuário não passar um pacote, usamos o exemplo válido padrão
    default_hex = "450000281c4640004011b82dc0a8013208080808"
    
    print(f" Usando pacote padrão (hex):\n{default_hex}\n")
    
    try:
        # 1. Converte a string hex para bytes brutos
        packet_bytes = bytes.fromhex(default_hex)
        
        # 2. Processa o cabeçalho
        parsed_packet = parse_ipv4_header(packet_bytes)
        
        # 3. Exibe os resultados formatados na tela
        print(" Resultado do Parsing com Sucesso:")
        print("-" * 35)
        for key, value in parsed_packet.items():
            print(f"{key.replace('_', ' ').title():<18}: {value}")
        print("-" * 35)
        
    except ValueError as e:
        print(f" Erro ao processar o pacote: {e}")
    except Exception as e:
        print(f" Ocorreu um erro inesperado: {e}")

if __name__ == "__main__":
    main()




