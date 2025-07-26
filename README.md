# Network Diagram Generator

Uma ferramenta em Python para detectar e visualizar conexões de rede ativas em hosts (Windows e Linux), correlacionando PIDs a nomes de processos e inferindo serviços/protocolos para gerar diagramas explicativos.

---

## Funcionalidades

* **Coleta de Dados Multiplataforma:** Coleta informações de conexão de rede usando `netstat -ano` (Windows) ou `ss -tunap` (Linux).
* **Mapeamento de Processos:** Associa PIDs a nomes e caminhos de executáveis utilizando a biblioteca `psutil`.
* **Inferência de Serviços/Protocolos:** Identifica serviços/protocolos comuns (HTTP, SSH, MySQL, etc.) com base nas portas utilizadas nas conexões.
* **Geração de Diagramas Visuais:** Cria diagramas de rede em formatos como PNG ou SVG, visualizando as conexões entre IPs, processos e destacando os serviços/protocolos ativos com a ferramenta Graphviz.

---

## Pré-requisitos

Para rodar este script, você precisará ter o Python e algumas bibliotecas e ferramentas adicionais instaladas.

1.  **Python 3.x:** (Versão 3.8 ou superior recomendada)
    * Verifique com `python --version` ou `python3 --version`.

2.  **Biblioteca Python `psutil`:**
    * Para mapear PIDs a processos.
    * Instalação: `pip install psutil`

3.  **Biblioteca Python `graphviz`:**
    * Interface Python para o software Graphviz.
    * Instalação: `pip install graphviz`

4.  **Software Graphviz:** (O motor de renderização de diagramas)
    * **Crucial:** O executável `dot` do Graphviz deve estar no `PATH` do seu sistema operacional.

---

## Como Instalar o Software Graphviz

### No Windows:

1.  Acesse o site oficial do Graphviz: [https://graphviz.org/download/](https://graphviz.org/download/)
2.  Baixe o instalador `.msi` mais recente para Windows (ex: `graphviz-X.XX.msi`).
3.  Execute o instalador. Durante o processo de instalação, **selecione a opção para adicionar o Graphviz ao `PATH` do sistema para todos os usuários**.
4.  Após a instalação, **reinicie seu terminal (Prompt de Comando ou PowerShell)**.
5.  **Verifique a instalação** executando no terminal:
    ```bash
    dot -V
    ```
    Se retornar a versão do Graphviz, a instalação está correta.

### No Linux (Ex: Ubuntu/Debian):

1.  Abra o terminal.
2.  Atualize os pacotes e instale o Graphviz:
    ```bash
    sudo apt update
    sudo apt install graphviz
    ```
3.  **Verifique a instalação** executando no terminal:
    ```bash
    dot -V
    ```
    Se retornar a versão do Graphviz, a instalação está correta.

---

## Como Usar

1.  **Clone o Repositório:**
    Abra seu terminal e clone este repositório:
    ```bash
    git clone [https://github.com/SeuUsuario/NetworkDiagramGenerator.git](https://github.com/SeuUsuario/NetworkDiagramGenerator.git)
    cd NetworkDiagramGenerator
    ```
    *(**Importante:** Substitua `SeuUsuario` pelo seu nome de usuário real no GitHub ao fornecer essas instruções.)*

2.  **Instale as Dependências Python:**
    Dentro da pasta `NetworkDiagramGenerator`, execute:
    ```bash
    pip install psutil graphviz
    ```
    *(Use `pip3` se `pip` não funcionar para Python 3.)*

3.  **Execute o Script:**
    No terminal, dentro da pasta do projeto, execute:
    ```bash
    python network_diagram_generator.py
    ```
    *(Ou `python3 network_diagram_generator.py` se `python` não funcionar.)*

4.  **Obtenha o Diagrama:**
    * O script imprimirá no console as conexões encontradas.
    * Após a execução, um arquivo de imagem (`network_diagram.png` por padrão) será gerado na **mesma pasta do script**. Este arquivo contém o diagrama visual das conexões de rede.

---

## Exemplo de Diagrama

(Aqui você pode adicionar uma imagem de exemplo do diagrama gerado após ter testado e gerado um em sua máquina, ou deixar em branco por enquanto)

---

## Contribuições

Contribuições são bem-vindas! Se você tiver ideias para melhorias ou encontrar algum bug, sinta-se à vontade para abrir uma *issue* ou enviar um *pull request*.

---

## Licença

Este projeto está licenciado sob a [MIT License](LICENSE).
