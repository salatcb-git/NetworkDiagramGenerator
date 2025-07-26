import subprocess
import os

def collect_netstat_data():
    """
    Executa o comando 'netstat -ano' no Windows e retorna a saída.
    """
    print("Coletando dados de conexão com 'netstat -ano'...")
    try:
        process = subprocess.run(['netstat', '-ano'], capture_output=True, text=True, check=True)
        return process.stdout
    except subprocess.CalledProcessError as e:
        print(f"Erro ao executar netstat: {e}")
        print(f"Stderr: {e.stderr}")
        return None
    except FileNotFoundError:
        print("Comando 'netstat' não encontrado. Certifique-se de que está no PATH do sistema.")
        return None

def parse_netstat_output(netstat_output):
    """
    Analisa a saída do netstat e extrai as informações das conexões.
    Retorna uma lista de dicionários, onde cada dicionário representa uma conexão.
    """
    connections = []
    lines = netstat_output.strip().split('\n')

    # Ignora as primeiras linhas (cabeçalhos e linhas vazias)
    # A linha que começa com 'Proto' é o cabeçalho
    data_started = False
    for line in lines:
        if line.startswith('  Proto'): # Encontra o cabeçalho
            data_started = True
            continue # Pula o cabeçalho em si
        if not data_started or not line.strip(): # Ignora linhas antes do cabeçalho ou linhas vazias
            continue

        # Divide a linha em partes. Usamos split() sem argumento para dividir por qualquer espaço
        # e descartar espaços múltiplos, e depois filtramos strings vazias.
        parts = line.strip().split()

        # Esperamos pelo menos 5 partes: Proto, Local Address, Foreign Address, State, PID
        if len(parts) >= 5:
            # Captura o protocolo, endereço local, remoto, estado e PID
            protocol = parts[0]
            local_address = parts[1]
            foreign_address = parts[2]
            state = parts[3]
            pid = parts[4] # O PID pode ser '0' ou um número real

            # A inferência básica do serviço por enquanto será apenas a porta
            # Poderíamos adicionar lógica mais tarde para mapear portas conhecidas (80 -> HTTP)

            connections.append({
                'protocol': protocol,
                'local_address': local_address,
                'foreign_address': foreign_address,
                'state': state,
                'pid': pid
            })
    return connections

def main():
    netstat_output = collect_netstat_data()
    if netstat_output:
        parsed_connections = parse_netstat_output(netstat_output)
        print("\n--- Conexões Analisadas ---")
        for conn in parsed_connections:
            print(f"Proto: {conn['protocol']}, Local: {conn['local_address']}, "
                  f"Foreign: {conn['foreign_address']}, State: {conn['state']}, PID: {conn['pid']}")
        print(f"\nTotal de conexões encontradas: {len(parsed_connections)}")
        print("\n--- Análise concluída ---")
    else:
        print("\nNão foi possível coletar ou analisar os dados do netstat.")

if __name__ == "__main__":
    if os.name == 'nt':
        main()
    else:
        print("Este script é projetado para rodar no Windows. Por favor, execute-o em um ambiente Windows.")
