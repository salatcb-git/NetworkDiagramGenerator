import subprocess
import os
import psutil
import re
import graphviz
import datetime
import socket # <--- Importação necessária para resolução de hostname

# Dicionário para mapear portas conhecidas a nomes de serviços
KNOWN_PORTS = {
    '7': 'Echo', '9': 'Discard', '13': 'Daytime', '17': 'Quote of the Day', '19': 'Chargen',
    '20': 'FTP Data', '21': 'FTP Control', '22': 'SSH (Secure Shell)', '23': 'Telnet',
    '25': 'SMTP (Simple Mail Transfer Protocol)', '53': 'DNS (Domain System)',
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
    '5060': 'SIP (Session Initialization Protocol)', '5061': 'SIP TLS',
    '5432': 'PostgreSQL Database', '5900': 'VNC (Virtual Network Computing)',
    '8000': 'HTTP (Alternate) / Web Server', '8080': 'HTTP Proxy / Web Server (Alternate)',
    '8443': 'HTTPS (Alternate) / Web Server', '27017': 'MongoDB Database'
}

# --- LISTA DE PORTAS CHAVE PARA FILTRAGEM ---
# Defina AQUI as portas que você *realmente* considera relevantes para a análise de firewall.
# Conexões que NÃO usam essas portas (local para LISTEN, estrangeira para ESTABLISHED) serão ignoradas.
SERVICE_PORTS_OF_INTEREST = {
    '22',   # SSH
    '23',   # Telnet (embora desencorajado, pode ser relevante em alguns contextos)
    '25',   # SMTP
    '53',   # DNS
    '80',   # HTTP
    '110',  # POP3
    '143',  # IMAP
    '389',  # LDAP
    '443',  # HTTPS
    '445',  # SMB/CIFS (compartilhamento de arquivos)
    '587',  # SMTP Submission
    '636',  # LDAPS
    '993',  # IMAPS
    '995',  # POP3S
    '1433', # Microsoft SQL Server
    '3306', # MySQL
    '3389', # RDP
    '5432', # PostgreSQL
    '5060', # SIP
    '5061', # SIP TLS
    '8000', # Portas comuns para servidores web alternativos
    '8080',
    '8443'
    # Adicione ou remova outras portas conforme sua necessidade de visibilidade.
    # Ex: '21' para FTP, '1521' para Oracle, etc.
}

# --- Configurações de Rede para o Diagrama ---
# Ajuste estes valores para o seu ambiente
LOCAL_HOST_IP_PREFIX = '192.168.1.' # Usado para determinar se um IP é da rede local (ex: '192.168.1.' para /24)
GATEWAY_IP = '192.168.1.1' # O IP do seu gateway/firewall

def is_same_subnet(ip_address, subnet_prefix):
    """Verifica se um endereço IP pertence à mesma sub-rede baseada em um prefixo."""
    return ip_address.startswith(subnet_prefix)


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
        # Adicionado encoding='latin-1' para tentar resolver problemas de caracteres especiais no Windows
        process = subprocess.run(command, capture_output=True, text=True, check=True, timeout=30, encoding='latin-1')
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
    except UnicodeDecodeError as e:
        print(f"Erro de decodificação de caracteres: {e}")
        print("Tentando com uma codificação diferente (ex: cp850 ou cp1252) pode resolver.")
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
    Se a porta não for conhecida, retorna "Serviço Desconhecido".
    """
    port_str = str(port).split(':')[-1]
    try:
        port_num = int(port_str)
        # Usa o KNOWN_PORTS apenas para mapear o nome, não para filtrar
        return KNOWN_PORTS.get(str(port_num), "Serviço Desconhecido")
    except ValueError:
        return "Porta Inválida"

def parse_connection_output(raw_output):
    connections = []
    lines = raw_output.strip().split('\n')

    is_windows_output = False
    # Procura a linha do cabeçalho do Windows de forma mais flexível
    for line in lines:
        if ('Proto' in line and 'local' in line.lower() and 'externo' in line.lower() and 'estado' in line.lower() and 'pid' in line.lower()) or \
           ('Proto' in line and 'Local Address' in line and 'Foreign Address' in line and 'State' in line and 'PID' in line):
            is_windows_output = True
            print("DEBUG: Cabeçalho de saída do Windows detectado (flexível).")
            break
            
    is_linux_output = False
    if lines and 'Netid' in lines[0] and 'State' in lines[0]: # Linux ss header check
        is_linux_output = True
        print("DEBUG: Cabeçalho de saída do Linux (ss) detectado.")

    data_started = False
    print("\n--- Iniciando análise da saída bruta ---")
    for i, line in enumerate(lines):
        stripped_line = line.strip()

        if not data_started:
            if (is_windows_output and (('Proto' in stripped_line and 'local' in stripped_line.lower() and 'externo' in stripped_line.lower() and 'estado' in stripped_line.lower() and 'pid' in stripped_line.lower()) or
                                       ('Proto' in stripped_line and 'Local Address' in stripped_line and 'Foreign Address' in stripped_line and 'State' in stripped_line and 'PID' in stripped_line))) or \
               (is_linux_output and stripped_line.startswith('Netid')):
                data_started = True
                continue
            else:
                continue
            
        if not stripped_line: # Ignora linhas vazias após o cabeçalho
            continue

        # Use re.split para lidar com múltiplos espaços como um único delimitador
        parts = re.split(r'\s+', stripped_line)

        protocol = ''
        local_address = ''
        foreign_address = ''
        state = ''
        pid_str = ''
        process_name_from_ss = ''

        if is_windows_output:
            if len(parts) >= 5: # Garante que há partes suficientes para Windows
                protocol = parts[0]
                local_address = parts[1]
                foreign_address = parts[2]
                state = parts[3]
                pid_str = parts[4]
            else:
                continue
        elif is_linux_output:
            # Padrão para ss: Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port users:(("process_name",pid=PID,fd=FD))
            if len(parts) >= 6:
                protocol = parts[0]
                state = parts[1]
                local_address = parts[4]
                foreign_address = parts[5]

                match_users_info = re.search(r'users:\(\("([^"]+)",pid=(\d+),fd=\d+\)\)', stripped_line)
                if match_users_info:
                    process_name_from_ss = match_users_info.group(1)
                    pid_str = match_users_info.group(2)
                else:
                    # Fallback para casos sem info de users (ex: kernel, ou outras infos no final)
                    if parts and parts[-1].isdigit():
                        pid_str = parts[-1]
                    elif len(parts) >= 2 and parts[-2].isdigit():
                        pid_str = parts[-2]
            else:
                continue

        # Se as informações essenciais não foram extraídas, pule esta linha.
        if not protocol or not local_address or not foreign_address or not pid_str:
            continue

        local_port = local_address.split(':')[-1] if ':' in local_address else ''
        foreign_port = foreign_address.split(':')[-1] if ':' in foreign_address else ''

        # Assegurar que as portas são numéricas para comparação
        try:
            local_port_num = int(local_port)
        except ValueError:
            local_port_num = -1 # Valor inválido para não ser comparado

        try:
            foreign_port_num = int(foreign_port)
        except ValueError:
            foreign_port_num = -1 # Valor inválido para não ser comparado
            
        service_name_foreign = get_service_name_from_port(foreign_port, protocol)
        service_name_local = get_service_name_from_port(local_port, protocol)
            
        process_info = get_process_info(pid_str)
            
        final_process_name = process_info['name']
        if is_linux_output and process_name_from_ss and ('Processo não encontrado' in final_process_name or 'Erro psutil' in final_process_name):
            final_process_name = process_name_from_ss

        # --- REGRAS DE FILTRAGEM REVISADAS COMEÇAM AQUI ---

        # 1. EXCLUIR TODAS as conexões de loopback.
        # Loopback IPv4: 127.0.0.1
        # Loopback IPv6: ::1
        # Qualquer conexão onde o endereço local OU estrangeiro for loopback será ignorada.
        local_ip_base = re.sub(r':\d+$', '', local_address).replace('[', '').replace(']', '')
        foreign_ip_base = re.sub(r':\d+$', '', foreign_address).replace('[', '').replace(']', '')

        if local_ip_base == '127.0.0.1' or local_ip_base == '::1' or \
           foreign_ip_base == '127.0.0.1' or foreign_ip_base == '::1':
            # print(f"DEBUG: Ignorando conexão de loopback: {stripped_line}")
            continue

        # 2. Focar em estados de conexão relevantes: ESTABLISHED e LISTENING.
        if state not in ['ESTABLISHED', 'LISTEN']:
            # print(f"DEBUG: Ignorando conexão em estado não relevante ({state}): {stripped_line}")
            continue

        # 3. Principal filtro: Incluir apenas conexões que usam portas de serviço de interesse
        # A conexão é considerada relevante se a porta local (para LISTEN) ou a porta estrangeira (para ESTABLISHED)
        # estiver na nossa lista SERVICE_PORTS_OF_INTEREST.
        is_local_port_of_interest = str(local_port_num) in SERVICE_PORTS_OF_INTEREST
        is_foreign_port_of_interest = str(foreign_port_num) in SERVICE_PORTS_OF_INTEREST

        if state == 'LISTENING':
            # Para serviços LISTENING, o que importa é a porta local estar na lista de interesse.
            if not is_local_port_of_interest:
                # print(f"DEBUG: Ignorando serviço LISTENING em porta não de interesse: {local_port} - {stripped_line}")
                continue
        elif state == 'ESTABLISHED':
            # Para conexões ESTABLISHED, a porta relevante para o administrador de rede é a *porta de serviço estrangeira*.
            # Se a porta estrangeira NÃO for de interesse, ignoramos a conexão.
            if not is_foreign_port_of_interest:
                # print(f"DEBUG: Ignorando conexão ESTABLISHED sem porta de serviço estrangeira conhecida: {foreign_port} - {stripped_line}")
                continue

        # --- REGRAS DE FILTRAGEM REVISADAS TERMINAM AQUI ---

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
            'service_foreign': service_name_foreign,
            'service_local': service_name_local
        })
    print("--- Análise da saída bruta concluída ---")
    return connections

def generate_network_diagram(connections, filename="network_diagram", format="png", current_hostname="", current_host_ip=""):
    """
    Gera um diagrama de rede a partir das conexões usando Graphviz.
    O diagrama será salvo como um arquivo de imagem (ex: .png).
    """
    # Obtém a data atual
    current_date = datetime.date.today().strftime("%Y-%m-%d")
    diagram_title = f"Diagrama de Conexões de Rede\nData de Criação/Revisão: {current_date}"

    dot = graphviz.Digraph(comment='Network Connections',
                           graph_attr={'rankdir': 'LR', 'label': diagram_title, 'labelloc': 't', 'fontsize': '20'},
                           node_attr={'fontname': 'Helvetica'},
                           edge_attr={'fontname': 'Helvetica'})

    # Conjuntos para armazenar nós únicos (IPs e processos) para evitar duplicação
    nodes = set()
    
    # Adicionar nós (IPs e Processos)
    for conn in connections:
        local_ip_full = conn['local_address']
        foreign_ip_full = conn['foreign_address']
        
        # Remove a porta do IP para o ID do nó, tratando IPv6
        local_ip_node = re.sub(r':\d+$', '', local_ip_full).replace('[', '').replace(']', '')
        foreign_ip_node = re.sub(r':\d+$', '', foreign_ip_full).replace('[', '').replace(']', '')

        # Nós de IP Local
        if local_ip_node not in nodes:
            node_label = local_ip_node
            node_color = 'lightblue'

            # Se o IP local corresponde ao IP da máquina que está executando o script, adicione o nome do host
            if current_host_ip and local_ip_node == current_host_ip:
                node_label = f"Este Host ({current_hostname})\n{local_ip_node}"
                node_color = 'skyblue' # Uma cor ligeiramente diferente para o host local
            
            dot.node(local_ip_node, node_label, shape='box', style='filled', color=node_color)
            nodes.add(local_ip_node)

        # Adiciona o nó do Gateway se ainda não existir
        if GATEWAY_IP not in nodes:
            # Novo rótulo para o gateway
            gateway_label = f"Gateway/Firewall\n{GATEWAY_IP}"
            dot.node(GATEWAY_IP, gateway_label, shape='box', style='filled', color='orange', fontcolor='black')
            nodes.add(GATEWAY_IP)

        # ### NOVA LÓGICA DE RESOLUÇÃO DE HOSTNAME AQUI ###
        # Nós de IP Estrangeiro (apenas se não for o gateway e não for um IP genérico)
        if foreign_ip_node and foreign_ip_node != '0.0.0.0' and foreign_ip_node != '*' and foreign_ip_node != '::' and foreign_ip_node != GATEWAY_IP and foreign_ip_node not in nodes:
            foreign_node_label = foreign_ip_node # Rótulo padrão é apenas o IP
            try:
                # Tenta resolver o nome de host para o IP estrangeiro
                # socket.gethostbyaddr retorna (hostname, aliaslist, ipaddrlist)
                foreign_hostname, _, _ = socket.gethostbyaddr(foreign_ip_node)
                # Se um hostname válido for encontrado e for diferente do próprio IP, use-o
                if foreign_hostname and foreign_hostname != foreign_ip_node:
                    foreign_node_label = f"{foreign_hostname}\n{foreign_ip_node}"
            except socket.herror:
                # Erro de host (e.g., IP não tem registro PTR, ou é um IP privado sem DNS reverso)
                pass 
            except socket.timeout:
                # A consulta DNS excedeu o tempo limite
                pass
            except Exception as e:
                # Captura outras exceções que possam ocorrer durante a resolução
                # print(f"Aviso: Não foi possível resolver o hostname para {foreign_ip_node}: {e}") # Descomente para depurar
                pass

            dot.node(foreign_ip_node, foreign_node_label, shape='box', style='filled', color='lightgreen')
            nodes.add(foreign_ip_node)
        # ### FIM DA NOVA LÓGICA ###
        
        # Nó do Processo Local
        # Cria um ID único para o processo incluindo o PID e o nome
        # Sanitiza o nome do processo para uso em ID de nó Graphviz
        sanitized_process_name = re.sub(r'[^a-zA-Z0-9_]', '', conn['process_name'])
        process_node_id = f"PID_{conn['pid']}_{sanitized_process_name}" 
        process_label = f"{conn['process_name']}\n(PID: {conn['pid']})"
        if process_node_id not in nodes:
            dot.node(process_node_id, process_label, shape='ellipse', style='filled', color='lightyellow')
            nodes.add(process_node_id)

    # Adicionar arestas (conexões)
    for conn in connections:
        local_ip_full = conn['local_address']
        foreign_ip_full = conn['foreign_address']
        
        local_ip_node = re.sub(r':\d+$', '', local_ip_full).replace('[', '').replace(']', '')
        foreign_ip_node = re.sub(r':\d+$', '', foreign_ip_full).replace('[', '').replace(']', '')

        sanitized_process_name = re.sub(r'[^a-zA-Z0-9_]', '', conn['process_name'])
        process_node_id = f"PID_{conn['pid']}_{sanitized_process_name}"

        # Aresta: Processo -> IP Local (representando o uso da porta local)
        label_process_to_local_ip = f"Usa Porta: {conn['local_port']}\n({conn['service_local']})"
        dot.edge(process_node_id, local_ip_node, label=label_process_to_local_ip, style='dashed', color='gray')


        # Aresta: IP Local -> IP Estrangeiro (conexão de rede principal)
        if conn['state'] == 'ESTABLISHED':
            # Se a conexão é para um IP na mesma sub-rede (exceto o gateway), desenhe direto
            if is_same_subnet(foreign_ip_node, LOCAL_HOST_IP_PREFIX) and foreign_ip_node != GATEWAY_IP:
                label_connection = f"{conn['protocol']} {conn['foreign_port']}\n({conn['service_foreign']})"
                dot.edge(local_ip_node, foreign_ip_node, label=label_connection, color='blue', penwidth='1.5')
            # Se a conexão é para o próprio gateway (tráfego direto para o roteador/firewall)
            elif foreign_ip_node == GATEWAY_IP:
                label_connection = f"{conn['protocol']} {conn['foreign_port']}\n({conn['service_foreign']})"
                dot.edge(local_ip_node, GATEWAY_IP, label=label_connection, color='purple', penwidth='1.5') # Cor diferente para tráfego para o gateway
            # Se a conexão é para a internet (não é local e não é o gateway)
            elif foreign_ip_node and foreign_ip_node != '0.0.0.0' and foreign_ip_node != '*' and foreign_ip_node != '::':
                # Conexão do host para o gateway (tráfego de saída para a internet)
                dot.edge(local_ip_node, GATEWAY_IP, label=f"Tráfego para Internet\n(Via {conn['protocol']} {conn['foreign_port']})", color='red', penwidth='2.5', style='bold')
                # Conexão do gateway para o IP externo
                label_connection_gateway_to_foreign = f"{conn['protocol']} {conn['foreign_port']}\n({conn['service_foreign']})"
                dot.edge(GATEWAY_IP, foreign_ip_node, label=label_connection_gateway_to_foreign, color='darkgreen', penwidth='1.5')
        
        elif conn['state'] == 'LISTENING' and conn['local_port']:
            # Para LISTENERS, a "conexão" é com o próprio IP local, representando que a porta está aberta para o mundo
            # E a aresta principal deve vir do IP local.
            label_listening = f"LISTEN {conn['local_port']}\n({conn['service_local']})"
            # Usar uma aresta para si mesmo para indicar que a porta está aberta para conexões
            dot.edge(local_ip_node, local_ip_node, label=label_listening, dir='none', color='orange', style='dotted', fontcolor='red')


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
        print("\n--- Saída bruta do comando de conexão ---")
        # print(raw_output) # Imprime a saída bruta para depuração - descomente se precisar ver
        print("--- Fim da saída bruta ---")

        parsed_connections = parse_connection_output(raw_output)
        
        # --- Obter Hostname e IP para rotulagem no diagrama ---
        current_hostname = ""
        current_host_ip = ""
        try:
            current_hostname = socket.gethostname()
            current_host_ip = socket.gethostbyname(current_hostname)
            print(f"Host local detectado: {current_hostname} ({current_host_ip})")
        except Exception as e:
            print(f"Não foi possível obter o nome ou IP do host local: {e}. O diagrama não terá essa identificação completa.")
            current_hostname = "Desconhecido" # Fallback para o nome
            current_host_ip = "" # Garante que está vazio se houve erro para não tentar comparar

        if parsed_connections:
            print(f"\nTotal de conexões relevantes encontradas: {len(parsed_connections)}")

            # Gerar o diagrama após a coleta e análise, passando o hostname e IP
            generate_network_diagram(parsed_connections, filename="network_diagram", format="png",
                                     current_hostname=current_hostname, current_host_ip=current_host_ip)
        else:
            print("\nNenhuma conexão relevante encontrada para análise ou diagrama.")
        print("\n--- Análise e Geração de Diagrama Concluídas ---")
    else:
        print("\nNão foi possível coletar ou analisar os dados de conexão.")

if __name__ == "__main__":
    main()
