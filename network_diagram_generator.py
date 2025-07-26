import subprocess
import os
import psutil
import re # Importa o módulo de expressões regulares para parsing mais robusto do ss

# Dicionário para mapear portas conhecidas a nomes de serviços
KNOWN_PORTS = {
    # TCP/UDP
    '7': 'Echo',
    '9': 'Discard',
    '13': 'Daytime',
    '17': 'Quote of the Day',
    '19': 'Chargen',
    '20': 'FTP Data',
    '21': 'FTP Control',
    '22': 'SSH (Secure Shell)',
    '23': 'Telnet',
    '25': 'SMTP (Simple Mail Transfer Protocol)',
    '53': 'DNS (Domain Name System)',
    '67': 'DHCP Server',
    '68': 'DHCP Client',
    '69': 'TFTP (Trivial File Transfer Protocol)',
    '80': 'HTTP (Hypertext Transfer Protocol)',
    '110': 'POP3 (Post Office Protocol v3)',
    '119': 'NNTP (Network News Transfer Protocol)',
    '123': 'NTP (Network Time Protocol)',
    '137': 'NetBIOS Name Service',
    '138': 'NetBIOS Datagram Service',
    '139': 'NetBIOS Session Service (SMB over NetBIOS)',
    '143': 'IMAP (Internet Message Access Protocol)',
    '161': 'SNMP (Simple Network Management Protocol)',
    '162': 'SNMP Trap',
    '389': 'LDAP (Lightweight Directory Access Protocol)',
    '443': 'HTTPS (HTTP Secure)',
    '445': 'SMB (Server Message Block) / CIFS',
    '500': 'ISAKMP / IKE (IPsec Key Exchange)',
    '514': 'Syslog',
    '587': 'SMTP (Submission)',
    '636': 'LDAPS (LDAP Secure)',
    '993': 'IMAPS (IMAP Secure)',
    '995': 'POP3S (POP3 Secure)',
    '1433': 'Microsoft SQL Server',
    '1521': 'Oracle Database',
    '3306': 'MySQL Database',
    '3389': 'RDP (Remote Desktop Protocol)',
    '5060': 'SIP (Session Initiation Protocol)',
    '5061': 'SIP TLS',
    '5432': 'PostgreSQL Database',
    '5900': 'VNC (Virtual Network Computing)',
    '8000': 'HTTP (Alternate) / Web Server',
    '8080': 'HTTP Proxy / Web Server (Alternate)',
    '8443': 'HTTPS (Alternate) / Web Server',
    '27017': 'MongoDB Database',
    '50000': 'SAP Router / Other Custom Applications' # Adicionei com base no exemplo que você pode ver
}

def collect_connection_data():
    """
    Detecta o SO e executa o comando apropriado para coletar dados de conexão.
    Retorna a saída bruta do comando.
    """
    print(f"Detectando sistema operacional: {os.name}")
    if os.name == 'nt':  # Windows
        print("Coletando dados de conexão com 'netstat -ano' no Windows...")
        command = ['netstat', '-ano']
    elif os.name == 'posix':  # Linux, macOS, etc.
        print("Coletando dados de conexão com 'ss -tunap' no Linux/Unix...")
        command = ['ss', '-tunap']
    else:
        print("Sistema operacional não suportado para coleta de dados de conexão.")
        return None

    try:
        # Adiciona timeout para evitar que o comando trave indefinidamente
        process = subprocess.run(command, capture_output=True, text=True, check=True, timeout=30)
        return process.stdout
    except subprocess.CalledProcessError as e:
        print(f"Erro ao executar comando: {e}")
        print(f"Stderr: {e.stderr}")
        return None
    except FileNotFoundError:
        print(f"Comando '{command[0]}' não encontrado. Certifique-se de que está no PATH do sistema.")
        return None
    except subprocess.TimeoutExpired:
        print(f"O comando '{command[0]}' excedeu o tempo limite.")
        return None

def get_process_info(pid):
    """
    Obtém o nome do processo e o caminho do executável a partir de um PID.
    Retorna um dicionário com 'name' e 'path' do processo.
    """
    if not pid or pid == '0' or pid == '-': # PID 0, vazio ou '-' para System/Kernel/Unknown
        return {'name': 'System/Kernel/Unknown', 'path': ''}
    try:
        p = psutil.Process(int(pid))
        return {
            'name': p.name(),
            'path': p.exe() # Retorna o caminho completo do executável
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        # NoSuchProcess: Processo não existe mais
        # AccessDenied: Permissão negada para acessar informações do processo (comum para processos de sistema sem privilégios)
        return {'name': 'Processo não encontrado/acessível', 'path': ''}
    except ValueError: # Caso o PID não seja um número
        return {'name': 'PID inválido', 'path': ''}
    except Exception as e:
        return {'name': f'Erro psutil: {e}', 'path': ''}

def get_service_name_from_port(port, protocol):
    """
    Retorna o nome de um serviço conhecido para uma dada porta.
    """
    # Remove qualquer ':::' ou '*' do endereço antes de tentar converter para int
    port_str = str(port).split(':')[-1] # Pega a última parte se for IPv6 ou algo assim
    try:
        port_num = int(port_str)
        # Verifica se a porta está no nosso dicionário de portas conhecidas
        return KNOWN_PORTS.get(str(port_num), "Serviço Desconhecido")
    except ValueError:
        return "Porta Inválida"

def parse_connection_output(raw_output):
    """
    Analisa a saída do netstat (Windows) ou ss (Linux) e extrai as informações das conexões,
    enriquecendo-as com nomes de processos e inferência de serviços.
    """
    connections = []
    lines = raw_output.strip().split('\n')

    is_windows_output = '  Proto' in lines[0] if lines else False
    is_linux_output = 'Netid' in lines[0] if lines else False

    data_started = False
    for line in lines:
        if is_windows_output and line.startswith('  Proto'):
            data_started = True
            continue
        elif is_linux_output and line.startswith('Netid'):
            data_started = True
            continue
        if not data_started or not line.strip():
            continue

        parts = line.strip().split()

        protocol = ''
        local_address = ''
        foreign_address = ''
        state = ''
        pid_str = ''
        process_name_from_ss = '' # Para capturar o nome do processo bruto do ss

        if is_windows_output:
            if len(parts) >= 5:
                protocol = parts[0]
                local_address = parts[1]
                foreign_address = parts[2]
                state = parts[3]
                pid_str = parts[4]
        elif is_linux_output:
            # Padrão para ss: Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port users:(("process_name",pid=PID,fd=FD))
            if len(parts) >= 6:
                protocol = parts[0]
                state = parts[1]
                local_address = parts[4]
                foreign_address = parts[5]

                # Tenta extrair PID e nome do processo da parte 'users:(("...",pid=...",...))'
                # Usando regex para maior robustez
                match_users_info = re.search(r'users:\(\("([^"]+)",pid=(\d+),fd=\d+\)\)', line)
                if match_users_info:
                    process_name_from_ss = match_users_info.group(1)
                    pid_str = match_users_info.group(2)
                else: # Fallback para casos sem info de users (ex: kernel, ou outras infos no final)
                    # No Linux, se não há 'users' info, o PID pode estar no final ou ser ausente.
                    # Vamos tentar pegar o último 'part' como PID se for numérico.
                    if parts[-1].isdigit():
                        pid_str = parts[-1]
                    elif parts[-2].isdigit(): # As vezes o PID esta na penultima posicao para alguns servicos
                         pid_str = parts[-2]
        
        # Extrai a porta do endereço local e estrangeiro
        local_port = local_address.split(':')[-1]
        foreign_port = foreign_address.split(':')[-1]

        # Inferência de serviço para a porta estrangeira (remota)
        service_name = get_service_name_from_port(foreign_port, protocol)
        
        # Enriquecer com o nome e caminho do processo (usando psutil)
        process_info = get_process_info(pid_str)
        
        # Se psutil não achou o nome, mas o ss forneceu, usamos o do ss
        final_process_name = process_info['name']
        if is_linux_output and process_name_from_ss and 'Processo não encontrado' in final_process_name:
            final_process_name = process_name_from_ss # Usa o nome do ss se psutil falhar ou for generico

        connections.append({
            'protocol': protocol,
            'local_address': local_address,
            'local_port': local_port, # Adicionado para facilitar a inferência
            'foreign_address': foreign_address,
            'foreign_port': foreign_port, # Adicionado para facilitar a inferência
            'state': state,
            'pid': pid_str,
            'process_name': final_process_name,
            'process_path': process_info['path'],
            'service': service_name # Novo campo para o serviço inferido
        })
    return connections


def main():
    raw_output = collect_connection_data()
    if raw_output:
        parsed_connections = parse_connection_output(raw_output)
        print("\n--- Conexões Analisadas e Enriquecidas ---")
        for conn in parsed_connections:
            print(f"Proto: {conn['protocol']}, Local: {conn['local_address']} (Port: {conn['local_port']}), "
                  f"Foreign: {conn['foreign_address']} (Port: {conn['foreign_port']} - {conn['service']}), "
                  f"State: {conn['state']}, PID: {conn['pid']} ({conn['process_name']})")
            if conn['process_path']:
                print(f"  Path: {conn['process_path']}")
        print(f"\nTotal de conexões encontradas: {len(parsed_connections)}")
        print("\n--- Análise concluída ---")
    else:
        print("\nNão foi possível coletar ou analisar os dados de conexão.")

if __name__ == "__main__":
    main()
