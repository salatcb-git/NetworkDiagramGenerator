import subprocess
import os
import psutil

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
        process = subprocess.run(command, capture_output=True, text=True, check=True)
        return process.stdout
    except subprocess.CalledProcessError as e:
        print(f"Erro ao executar comando: {e}")
        print(f"Stderr: {e.stderr}")
        return None
    except FileNotFoundError:
        print(f"Comando '{command[0]}' não encontrado. Certifique-se de que está no PATH do sistema.")
        return None

def get_process_info(pid):
    """
    Obtém o nome do processo e o caminho do executável a partir de um PID.
    Retorna um dicionário com 'name' e 'path' do processo.
    """
    if not pid or pid == '0': # PID 0 geralmente é para o System Idle Process ou kernel, ou vazio
        return {'name': 'System/Kernel/Unknown', 'path': ''}
    try:
        p = psutil.Process(int(pid))
        return {
            'name': p.name(),
            'path': p.exe() # Retorna o caminho completo do executável
        }
    except psutil.NoSuchProcess:
        return {'name': 'Processo não encontrado', 'path': ''}
    except ValueError: # Caso o PID não seja um número (ex: '-')
        return {'name': 'PID inválido', 'path': ''}
    except Exception as e:
        return {'name': f'Erro psutil: {e}', 'path': ''}

def parse_connection_output(raw_output):
    """
    Analisa a saída do netstat (Windows) ou ss (Linux) e extrai as informações das conexões.
    Retorna uma lista de dicionários, onde cada dicionário representa uma conexão.
    """
    connections = []
    lines = raw_output.strip().split('\n')

    # Detecta o tipo de output baseado no cabeçalho ou no comando.
    # No Windows, a linha de cabeçalho começa com '  Proto'
    # No Linux, a linha de cabeçalho começa com 'Netid'
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
        pid = ''
        process_name_raw = '' # Para capturar o nome do processo bruto do ss

        if is_windows_output:
            if len(parts) >= 5:
                protocol = parts[0]
                local_address = parts[1]
                foreign_address = parts[2]
                state = parts[3]
                pid = parts[4]
        elif is_linux_output:
            # Ex: tcp ESTAB 0 0 192.168.1.100:43210 104.26.10.123:443 users:(("firefox",pid=1234,fd=99))
            if len(parts) >= 6: # Pelo menos 6 partes para TCP/UDP sem o users info
                protocol = parts[0]
                state = parts[1]
                local_address = parts[4] # No ss, é a 5ª coluna
                foreign_address = parts[5] # No ss, é a 6ª coluna

                # A parte do PID/processo vem no final, dentro de "users:(("..."))"
                # Precisamos procurar por "pid=" na linha
                pid_match = [p for p in parts if 'pid=' in p]
                if pid_match:
                    # Ex: pid=1234,
                    pid_str = pid_match[0]
                    try:
                        pid = pid_str.split('pid=')[1].split(',')[0].strip(')')
                    except IndexError:
                        pid = '' # Não conseguiu extrair o PID
                
                # Para o nome do processo, tentamos extrair da mesma parte que o PID
                process_name_match = [p for p in parts if 'users:(("' in p]
                if process_name_match:
                    # Ex: users:(("firefox",pid=1234,fd=99))
                    # Precisamos extrair 'firefox'
                    try:
                        process_name_raw = process_name_match[0].split('(("')[1].split('",')[0]
                    except IndexError:
                        process_name_raw = ''
                
        if protocol and local_address and foreign_address: # Assegura que a linha foi parseada com sucesso
            # Enriquecer com o nome e caminho do processo (usando psutil)
            # Para o Linux, se já extraímos o nome do processo do 'ss', podemos priorizá-lo
            # ou usar psutil para confirmar/obter o caminho
            process_info = get_process_info(pid)
            
            # Se psutil não achou o nome, mas o ss forneceu, usamos o do ss
            # ou se quisermos o caminho completo, psutil é melhor
            final_process_name = process_info['name']
            if is_linux_output and process_name_raw and 'Processo não encontrado' in final_process_name:
                final_process_name = process_name_raw # Usa o nome do ss se psutil falhar ou for generico

            connections.append({
                'protocol': protocol,
                'local_address': local_address,
                'foreign_address': foreign_address,
                'state': state,
                'pid': pid,
                'process_name': final_process_name,
                'process_path': process_info['path']
            })
    return connections


def main():
    raw_output = collect_connection_data()
    if raw_output:
        parsed_connections = parse_connection_output(raw_output)
        print("\n--- Conexões Analisadas e Enriquecidas ---")
        for conn in parsed_connections:
            print(f"Proto: {conn['protocol']}, Local: {conn['local_address']}, "
                  f"Foreign: {conn['foreign_address']}, State: {conn['state']}, "
                  f"PID: {conn['pid']} ({conn['process_name']})")
            if conn['process_path']:
                print(f"  Path: {conn['process_path']}")
        print(f"\nTotal de conexões encontradas: {len(parsed_connections)}")
        print("\n--- Análise concluída ---")
    else:
        print("\nNão foi possível coletar ou analisar os dados de conexão.")

if __name__ == "__main__":
    main()
