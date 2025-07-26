import subprocess
import os
import psutil
import re
import graphviz # Importa a biblioteca graphviz

# Dicionário para mapear portas conhecidas a nomes de serviços
KNOWN_PORTS = {
    # TCP/UDP
    '7': 'Echo', '9': 'Discard', '13': 'Daytime', '17': 'Quote of the Day', '19': 'Chargen',
    '20': 'FTP Data', '21': 'FTP Control', '22': 'SSH (Secure Shell)', '23': 'Telnet',
    '25': 'SMTP (Simple Mail Transfer Protocol)', '53': 'DNS (Domain Name System)',
    '67': 'DHCP Server', '68': 'DHCP Client', '69': 'TFTP (Trivial File Transfer Protocol)',
    '80': 'HTTP (Hypertext Transfer Protocol)', '110': 'POP3 (Post Office Protocol v3)',
    '119': 'NNTP (Network News Transfer Protocol)', '123': 'NTP (Network Time Protocol)',
    '137': 'NetBIOS Name Service', '138': 'NetBIOS Datagram Service',
    '139': 'NetBIOS Session Service (SMB over NetBIOS)', '143': 'IMAP (Internet Message Access Protocol)',
    '161': 'SNMP (Simple Network Management Protocol)', '162': 'SNMP Trap',
    '389': 'LDAP (Lightweight Directory Access Protocol)', '443': 'HTTPS (HTTP Secure)',
    '445': 'SMB (Server Message Block) / CIFS', '500': 'ISAKMP / IKE (IPsec Key Exchange)',
    '514': 'Syslog', '587': 'SMTP (Submission)', '636': 'LDAPS (LDAP Secure)',
    '993': 'IMAPS (IMAP Secure)', '995': 'POP3S (POP3 Secure)', '1433': 'Microsoft SQL Server',
    '1521': 'Oracle Database', '3306': 'MySQL Database', '3389': 'RDP (Remote Desktop Protocol)',
    '5060': 'SIP (Session Initiation Protocol)', '5061': 'SIP TLS',
    '5432': 'PostgreSQL Database', '5900': 'VNC (Virtual Network Computing)',
    '8000': 'HTTP (Alternate) / Web Server', '8080': 'HTTP Proxy / Web Server (Alternate)',
    '8443': 'HTTPS (Alternate) / Web Server', '27017': 'MongoDB Database',
    '50000': 'SAP Router / Other Custom Applications',
    '49152-65535': 'Ephemeral Ports (Usually Client Connections)' # Faixa comum de portas efêmeras
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
    if not pid or pid == '0' or pid == '-':
        return {'name': 'System/Kernel/Unknown', 'path': ''}
    try:
        p = psutil.Process(int(pid))
        return {
            'name': p.name(),
            'path': p.exe()
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return {'name': 'Processo não encontrado/acessível', 'path': ''}
    except ValueError:
        return {'name': 'PID inválido', 'path': ''}
    except Exception as e:
        return {'name': f'Erro psutil: {e}', 'path': ''}

def get_service_name_from_port(port, protocol):
    """
    Retorna o nome de um serviço conhecido para uma dada porta.
    Também verifica se a porta está na faixa de portas efêmeras.
    """
    port_str = str(port).split(':')[-1]
    try:
        port_num = int(port_str)
        # Verifica portas efêmeras (comum em conexões de saída de clientes)
        if 49152 <= port_num <= 65535:
            return "Porta Efêmera (Cliente)"
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
        process_name_from_ss = ''

        if is_windows_output:
            if len(parts) >= 5:
                protocol = parts[0]
                local_address = parts[1]
                foreign_address = parts[2]
                state = parts[3]
                pid_str = parts[4]
        elif is_linux_output:
            if len(parts) >= 6:
                protocol = parts[0]
                state = parts[1]
                local_address = parts[4]
                foreign_address = parts[5]

                match_users_info = re.search(r'users:\(\("([^"]+)",pid=(\d+),fd=\d+\)\)', line)
                if match_users_info:
                    process_name_from_ss = match_users_info.group(1)
                    pid_str = match_users_info.group(2)
                else:
                    if parts[-1].isdigit():
                        pid_str = parts[-1]
                    elif parts[-2].isdigit():
                         pid_str = parts[-2]
        
        # Extrai a porta do endereço local e estrangeiro
        # Lida com endereços IPv6 que podem ter múltiplos ':'
        local_port = local_address.split(':')[-1] if ':' in local_address else ''
        foreign_port = foreign_address.split(':')[-1] if ':' in foreign_address else ''

        service_name_foreign = get_service_name_from_port(foreign_port, protocol)
        service_name_local = get_service_name_from_port(local_port, protocol) # Também para a porta local

        process_info = get_process_info(pid_str)
        
        final_process_name = process_info['name']
        if is_linux_output and process_name_from_ss and 'Processo não encontrado' in final_process_name:
            final_process_name = process_name_from_ss

        connections.append({
            'protocol': protocol,
            'local_address': local_address,
            'local_port': local_port,
            'foreign_address': foreign_address,
            'foreign_port': foreign_port,
            'state': state,
            'pid': pid_str,
            'process_name': final_process_name,
            'process_path': process_info['path'],
            'service_foreign': service_name_foreign, # Serviço da porta remota
            'service_local': service_name_local # Serviço da porta local (útil para LISTENERS)
        })
    return connections

def generate_network_diagram(connections, filename="network_diagram", format="png"):
    """
    Gera um diagrama de rede a partir das conexões usando Graphviz.
    O diagrama será salvo como um arquivo de imagem (ex: .png).
    """
    dot = graphviz.Digraph(comment='Network Connections', graph_attr={'rankdir': 'LR'}) # LR = Left to Right

    # Conjuntos para armazenar nós únicos (IPs e processos) para evitar duplicação
    nodes = set()
    
    # Dicionário para armazenar informações detalhadas de nós (IPs e processos)
    # { 'IP_ou_Processo': {'label': '...', 'shape': '...', 'color': '...'} }
    node_details = {}

    # Adicionar nós (IPs e Processos)
    for conn in connections:
        local_ip = conn['local_address'].split(':')[0] if ':' in conn['local_address'] else conn['local_address']
        foreign_ip = conn['foreign_address'].split(':')[0] if ':' in conn['foreign_address'] else conn['foreign_address']

        # Nós de IP Local
        if local_ip not in nodes:
            dot.node(local_ip, local_ip, shape='box', style='filled', color='lightblue', fontname='Helvetica')
            nodes.add(local_ip)
            node_details[local_ip] = {'label': local_ip, 'shape': 'box', 'color': 'lightblue'}

        # Nós de IP Estrangeiro
        if foreign_ip and foreign_ip != '0.0.0.0' and foreign_ip != '*' and foreign_ip not in nodes:
            dot.node(foreign_ip, foreign_ip, shape='box', style='filled', color='lightgreen', fontname='Helvetica')
            nodes.add(foreign_ip)
            node_details[foreign_ip] = {'label': foreign_ip, 'shape': 'box', 'color': 'lightgreen'}
        
        # Nó do Processo Local
        process_node_id = f"PID_{conn['pid']}_{conn['process_name']}"
        process_label = f"{conn['process_name']}\n(PID: {conn['pid']})"
        if process_node_id not in nodes:
            dot.node(process_node_id, process_label, shape='ellipse', style='filled', color='lightyellow', fontname='Helvetica')
            nodes.add(process_node_id)
            node_details[process_node_id] = {'label': process_label, 'shape': 'ellipse', 'color': 'lightyellow'}

    # Adicionar arestas (conexões)
    for conn in connections:
        local_ip = conn['local_address'].split(':')[0] if ':' in conn['local_address'] else conn['local_address']
        foreign_ip = conn['foreign_address'].split(':')[0] if ':' in conn['foreign_address'] else conn['foreign_address']
        
        process_node_id = f"PID_{conn['pid']}_{conn['process_name']}"

        # Aresta: Processo -> IP Local (representando o uso da porta local)
        label_local_port = f"Porta Local: {conn['local_port']}\n({conn['service_local']})"
        dot.edge(process_node_id, local_ip, label=label_local_port, style='dashed', color='gray')

        # Aresta: IP Local -> IP Estrangeiro (conexão de rede principal)
        # O label da aresta deve indicar o protocolo/serviço da conexão
        if foreign_ip and foreign_ip != '0.0.0.0' and foreign_ip != '*':
            label_connection = f"{conn['protocol']} {conn['foreign_port']}\n({conn['service_foreign']})"
            dot.edge(local_ip, foreign_ip, label=label_connection, color='blue', penwidth='1.5')
        elif conn['state'] == 'LISTENING':
            # Para LISTENERS, a "conexão" é com o próprio IP local, representando que a porta está aberta para o mundo
            label_listening = f"LISTEN {conn['local_port']}\n({conn['service_local']})"
            dot.edge(local_ip, local_ip, label=label_listening, dir='none', color='orange', style='dotted', fontcolor='red')


    try:
        # Renderiza o gráfico
        print(f"\nGerando diagrama de rede em '{filename}.{format}'...")
        dot.render(filename, format=format, cleanup=True, view=False) # view=False para não abrir automaticamente
        print(f"Diagrama gerado com sucesso: {filename}.{format}")
    except graphviz.backend.ExecutableNotFound:
        print("\nERRO: O executável Graphviz 'dot' não foi encontrado.")
        print("Certifique-se de que o software Graphviz está instalado e seu diretório 'bin' foi adicionado ao PATH do sistema.")
        print("Instruções de instalação: https://graphviz.org/download/")
    except Exception as e:
        print(f"\nERRO ao gerar o diagrama: {e}")


def main():
    raw_output = collect_connection_data()
    if raw_output:
        parsed_connections = parse_connection_output(raw_output)
        
        if parsed_connections:
            print("\n--- Conexões Analisadas e Enriquecidas ---")
            for conn in parsed_connections:
                print(f"Proto: {conn['protocol']}, Local: {conn['local_address']}:{conn['local_port']} ({conn['service_local']}), "
                      f"Foreign: {conn['foreign_address']}:{conn['foreign_port']} ({conn['service_foreign']}), "
                      f"State: {conn['state']}, PID: {conn['pid']} ({conn['process_name']})")
                if conn['process_path']:
                    print(f"  Path: {conn['process_path']}")
            print(f"\nTotal de conexões encontradas: {len(parsed_connections)}")

            # Gerar o diagrama após a coleta e análise
            generate_network_diagram(parsed_connections, filename="network_diagram", format="png")
        else:
            print("\nNenhuma conexão relevante encontrada para análise ou diagrama.")
        print("\n--- Análise e Geração de Diagrama Concluídas ---")
    else:
        print("\nNão foi possível coletar ou analisar os dados de conexão.")

if __name__ == "__main__":
    main()
