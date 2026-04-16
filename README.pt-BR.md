🔗 Available in [English](./README.md).

---

# Pipeline AppSec - Orquestração de Segurança Centralizada  

Este repositório centraliza o pipeline de Segurança de Aplicações (AppSec), fornecendo varreduras automatizadas e orientadas por políticas para os projetos da organização. Construído com GitHub Actions e uma camada de orquestração em Python, ele garante conformidade, facilita o gerenciamento de falsos positivos e oferece uma aplicação flexível de políticas sem comprometer a velocidade do desenvolvimento.  

## Estratégia de Arquitetura  

O pipeline foi pensado em funcionar como um hub, onde os repositórios individuais chamam um workflow reutilizável centralizado. Isso permite que as políticas e ferramentas de segurança sejam mantidas em um único lugar, enquanto a execução ocorre de forma nativa no fluxo de PR dos desenvolvedores.  

- **Orquestração via GitHub Actions (`appsec-pipeline.yml`):**
    O orquestrador executa as ferramentas de segurança em jobs paralelos para otimizar o tempo de resposta. Cada ferramenta exporta os resultados no formato padronizado SARIF e os armazena como artefatos.
    
- **Security GATE (`gate.py`):**
    Para evitar a falta de contexto dos códigos de saída (_exit codes_) nativos das ferramentas, o job `security-gate` consolida todos os artefatos SARIF. Um script Python analisa os dados e os valida contra uma política de severidade centralizada (`severity-policy.yml`).
    
- **Gestão de Achados e Falsos Positivos (`exception_manager.py` & `security-exceptions.yml`):**
    O tratamento de falsos positivos é isolado do código-fonte, dispensando comentários de supressão (_inline comments_). Através de um workflow dedicado, os times de AppSec utilizam a interface do GitHub Actions para gerenciar exceções. As vulnerabilidades autorizadas são armazenadas no `exception.yml`, e o core do sistema as filtra antes da validação final do GATE.
    
- **Onboarding Automatizado (`setup_repo.py`):**
    A integração de novos repositórios é feita via script, que configura automaticamente as regras de proteção de branch (tornando o GATE obrigatório e protegendo a branch principal) e propaga os arquivos de chamada do workflow.
    
---

## Ferramentas e Justificativas

Priorizamos ferramentas _open-source_ de alto desempenho para evitar o aprisionamento tecnológico (_vendor lock-in_) e garantir total transparência sobre as regras de detecção.

|**Domínio**|**Ferramenta**|**Justificativa**|
|---|---|---|
|**SAST**|**Semgrep**|Leve e veloz. A sintaxe de regras é idêntica ao código-fonte, facilitando a criação de políticas internas customizadas.|
|**SCA**|**Trivy**|Referência em mapeamento de vulnerabilidades (CVEs) em dependências e pacotes de código aberto com baixo índice de erro.|
|**IaC**|**Trivy**|Consolidação de ferramentas ao validar infraestrutura (Terraform, K8s, Docker) com o mesmo motor de scan do SCA.|
|**Secrets**|**Gitleaks**|Especializado em detectar chaves de API e tokens expostos no histórico do Git de forma extremamente performática.|
|**Mobile SAST**|**MobSFscan**|Focado especificamente em vulnerabilidades de iOS e Android que scanners genéricos costumam ignorar.|

---

## Governança e Execução

O pipeline separa a visibilidade da obrigatoriedade. O objetivo é dar feedback constante sem interromper o fluxo de trabalho por questões menores.

### Bloqueios vs. Alertas

O comportamento é definido pelo `severity-policy.yml`, que estabelece um limite de bloqueio (`block_on`) para cada categoria de vulnerabilidade.

- **Não Bloqueantes:** Achados abaixo do limite (ex: `LOW`) aparecem no _Step Summary_ do GitHub para fins de higiene de código, mas **não interrompem** o pipeline.
    
- **Bloqueantes:** Vulnerabilidades que atingem o limite (ex: `HIGH`) forçam a falha do job `security-gate`, impedindo o merge do Pull Request na branch principal.
    

### Exceções (Supressão)

Caso um item bloqueante seja um falso positivo ou risco aceito, o time de AppSec pode suprimí-lo via workflow de gestão. Uma vez no `exception.yml`, o item é ignorado pelo GATE e o pipeline segue com sucesso.

### Bypass de Emergência

Em situações críticas (ex: _hotfix_ onde não há tempo para o processo de exceção), o time de AppSec pode contornar o bloqueio comentando `/sec-bypass <justificativa>` no PR. O job `check-bypass` valida o comando e o GATE libera o deploy, registrando o responsável e o motivo para futuras auditorias.

---

## Repositórios Vulneráveis Integrados

Abaixo estão os 4 repositórios vulneráveis usados para integração e testes do pipeline:

- **OWASP Juice Shop (Node.js/TypeScript - Web)** — https://github.com/jvrajunior/juice-shop
- **VAmPI (Python/Flask - API)** — https://github.com/jvrajunior/VAmPI
- **Terragoat (Terraform - AWS)** — https://github.com/jvrajunior/terragoat
- **diva-android (Java - Android)** — https://github.com/jvrajunior/diva-android