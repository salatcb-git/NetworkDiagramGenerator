# Network Diagram Generator 🌐

---

## Visão Geral

O **Network Diagram Generator** é uma ferramenta em desenvolvimento que visa simplificar a **descoberta e visualização de conexões de rede ativas** em hosts, facilitando a compreensão da topologia de comunicação e dos fluxos de dados dentro de uma infraestrutura.

Nosso objetivo é ir além de um simples diagrama, **explicando as conexões** encontradas ao associá-las a processos e serviços. Dessa forma enxergamos o **Network Diagram Generator** como uma ferramenta de apoio para entidades que precisam manter documentado a topologia de rede do ambiente de avaliação, em conformidade com o PCI-DSS. Ao final desse projeto um Diagrama de rede será gerado baseado nos dados coletados, e dessa forma será possível validar se as conexões existentes no ambiente são somente aquelas que precisam realmente existir.


---

## Motivação do Projeto

Em ambientes de TI complexos, entender as comunicações entre servidores, aplicações e endpoints é um desafio constante. Auditorias de segurança, troubleshooting de rede e documentação da infraestrutura se beneficiam enormemente de uma visão clara de "quem está falando com quem e por quê".

Este projeto nasce da necessidade de automatizar a geração de diagramas de rede dinâmicos e informativos, que sirvam como um recurso valioso para auditores, analistas de segurança e engenheiros de infraestrutura.

---

## Funcionalidades Atuais (MVP)

Atualmente, o projeto foca na coleta e análise inicial de dados de hosts Windows:

* **Coleta de Dados de Conexão:** Executa o comando `netstat -ano` para obter informações detalhadas sobre as conexões TCP/UDP ativas e as portas em escuta.
* **Parsing da Saída do Netstat:** Processa a saída bruta do `netstat` para extrair dados estruturados como Protocolo, Endereço Local, Endereço Remoto, Estado da Conexão e PID (Process ID) associado.

---

## Próximos Passos (Roadmap)

Estamos trabalhando para expandir as capacidades da ferramenta, incluindo:

* **Inferência de Serviços/Aplicações:** Mapear portas e PIDs a serviços/aplicações conhecidas (ex: 80/HTTP, 443/HTTPS, 3389/RDP).
* **Geração de Diagramas Visuais:** Utilizar bibliotecas como Graphviz para criar diagramas de rede a partir dos dados coletados.
* **Suporte a Múltiplos Hosts:** Capacidade de coletar dados de diversos hosts na rede e consolidá-los em um único diagrama.
* **Compatibilidade com Linux:** Estender a coleta de dados para sistemas operacionais baseados em Linux.
* **Integração com Informações de Processos:** Obter nomes dos processos associados aos PIDs para maior clareza.
* **Interface Interativa:** Desenvolver uma interface (CLI aprimorada ou web) para facilitar o uso e a visualização.

---

## Como Usar (Atualmente)

Para rodar a versão atual do script:

1.  **Pré-requisitos:**
    * Python 3.x instalado.
    * Sistema Operacional Windows (este script utiliza `netstat -ano`).

2.  **Clone o Repositório:**
    ```bash
    git clone [https://github.com/salatcb-git/NetworkDiagramGenerator.git](https://github.com/salatcb-git/NetworkDiagramGenerator.git)
    cd NetworkDiagramGenerator
    ```

3.  **Execute o Script:**
    ```bash
    python network_diagram_generator.py
    ```

    A saída mostrará as conexões de rede coletadas e analisadas no seu console.

---

---

## Contribuição

Contribuições são bem-vindas! Se você tiver ideias, sugestões de melhoria ou quiser contribuir com código, por favor:

1.  Faça um fork do repositório.
2.  Crie uma nova branch para suas alterações (`git checkout -b feature/sua-feature`).
3.  Faça suas alterações e commit (`git commit -m 'feat: adiciona nova funcionalidade'`).
4.  Envie suas alterações (`git push origin feature/sua-feature`).
5.  Abra um Pull Request descrevendo suas mudanças.

---

## Licença

Este projeto está licenciado sob a [MIT License](https://opensource.org/licenses/MIT).

---

## Contato

* **Salas Username:** [Meu Link do Git](https://github.com/salatcb-git)
* **LinkedIn:** (https://www.linkedin.com/in/salatiel-barbosa-b5331067/)
