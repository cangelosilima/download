# Deployment Audit — PowerShell

Kit para coletar snapshots locais dos servidores e comparar deployments e requisitos entre DEV, OT e PRD. O nome OT é configurável; use UAT se for o nome adotado pela equipe.

O coletor consulta o servidor em que é executado. O comparador trabalha offline com os JSONs e produz HTML autocontido: não requer IIS, banco, Node, CDN ou conexão com os servidores.

## Arquivos

- `Export-DeploymentSnapshot.ps1`: inventário local, gera um JSON por servidor.
- `Compare-DeploymentSnapshots.ps1`: comparação entre dois JSONs ou validação de um JSON isolado.
- `DeploymentAudit.psm1`: parsers, coletores, regras e proteção de valores.
- `manifest.example.json`: lista de componentes, seletores por ambiente, requisitos e de/paras.
- `report-template.html`: interface do relatório.
- `examples/`: snapshots e relatório demonstrativos, manifesto mínimo e contrato para adaptadores.
- `tests/Test-DeploymentAudit.ps1`: testes do motor e parsers, sem dependência de Pester.

Mantenha os scripts, módulo e template na mesma pasta. Os dados demonstrativos são fictícios.

## Começar

1. Copie `manifest.example.json` para `manifest.json`.
2. Substitua nomes de serviços/sites/tasks, contas, pastas, URLs e thumbprints pelos valores reais. Remova os componentes que não pertencem àquele grupo de servidores. Os exemplos de frameworks são requisitos ilustrativos; ajuste as versões às aplicações.
3. Use a mesma cópia do manifesto nos servidores comparados. Cada item tem um `id` lógico estável, independente do nome físico no ambiente.
4. Execute o coletor em Windows PowerShell 5.1 **64 bits** (`powershell.exe`). Use uma conta autorizada a ler IIS, serviços, tasks, Registro, certificados, diretórios e política local. Uma sessão elevada facilita a cobertura; acesso negado é reportado como incompleto.

```powershell
# No servidor DEV
powershell.exe -NoProfile -File .\Export-DeploymentSnapshot.ps1 `
  -Manifest .\manifest.json -Environment DEV -Output .\out\dev-api01.json

# No servidor OT, depois de copiar o mesmo kit/manifesto
powershell.exe -NoProfile -File .\Export-DeploymentSnapshot.ps1 `
  -Manifest .\manifest.json -Environment OT -Output .\out\ot-api01.json

# No servidor PRD
powershell.exe -NoProfile -File .\Export-DeploymentSnapshot.ps1 `
  -Manifest .\manifest.json -Environment PRD -Output .\out\prd-api01.json
```

Transfira os JSONs para a máquina de análise. O comparador aceita Windows PowerShell 5.1 ou PowerShell 7; o coletor usa as APIs e módulos do Windows PowerShell.

```powershell
powershell.exe -NoProfile -File .\Compare-DeploymentSnapshots.ps1 `
  -Manifest .\manifest.json `
  -Left .\out\dev-api01.json -Right .\out\ot-api01.json `
  -OutputHtml .\out\dev-vs-ot.html -OutputJson .\out\dev-vs-ot.diff.json -Open

powershell.exe -NoProfile -File .\Compare-DeploymentSnapshots.ps1 `
  -Manifest .\manifest.json `
  -Left .\out\ot-api01.json -Right .\out\prd-api01.json `
  -OutputHtml .\out\ot-vs-prd.html

# Validar somente um servidor contra os requisitos, sem comparar ambientes
powershell.exe -NoProfile -File .\Compare-DeploymentSnapshots.ps1 `
  -Manifest .\manifest.json -Left .\out\prd-api01.json `
  -OutputHtml .\out\validacao-prd.html
```

O HTML tem busca, filtro por status/categoria, paginação e exportação dos resultados filtrados. Os snapshots incluem data/hora UTC, servidor, ambiente, hash do manifesto, resultado de cada coletor, campos e problemas de cobertura.

## Escopo da coleta

| Área | Evidência coletada |
|---|---|
| IIS | Site/aplicação, estado do site e pool, identidade, CLR do pool, modo de pipeline, 32 bits, recycling, process model selecionado, variáveis do pool, bindings/certificados, virtual directories, autenticação herdada selecionada e SSL flags |
| APIs | Pasta física da aplicação IIS, configurações, ACL da pasta e arquivos, versões/hashes dos binários selecionados, GET de health check opcional |
| Windows Services | Nome, estado, início automático/manual, conta, dependências, delayed start, comando protegido, PID informativo, SDDL, variáveis de ambiente próprias do serviço, pasta/configurações/binários |
| Windows Task Scheduler | Identidade/logon/run level, enabled, definição de triggers/actions/settings/principals, estado, último resultado/execução, próxima execução, SDDL e configurações na pasta informada/descoberta |
| MSMQ local | Presença e metadados expostos pelo módulo MSMQ, ACL, estado do serviço MSMQ, contagens informativas; não recebe, envia, apaga ou inspeciona mensagens |
| Certificados | LocalMachine/store/thumbprint selecionado, subject/issuer, SANs/EKUs, validade, private key presente e ACL do arquivo de chave RSA CSP/CNG quando disponível |
| Permissões | DACL/owner/SDDL de pastas e arquivos selecionados, SDDL de serviços/tasks, ACL de filas/chaves, membros diretos dos grupos locais escolhidos e direitos de usuário via exportação da política mesclada |
| Windows Features | Estados Installed/Available/Removed via ServerManager |
| Softwares | Entradas de desinstalação HKLM de 32/64 bits: nome, versão, publisher e localização |
| .NET | .NET Framework via Registro; runtimes e SDKs x64/x86 nas pastas padrão `Program Files\dotnet`; versão do ANCM quando encontrado |
| Outros schedulers/MQs | Contrato JSON por arquivo ou endpoint HTTPS próprio; integração específica necessária |

O coletor não inicia/para aplicações, não instala features e não altera ACLs. Apenas grava o snapshot e usa arquivos temporários para `secedit /export`. Health checks e adaptadores HTTP fazem GET nos endpoints explicitamente configurados.

## Descoberta dos arquivos .NET

IIS: resolve o `physicalPath` da raiz da aplicação selecionada. Serviço: resolve o executável registrado no SCM ou uma DLL absoluta hospedada por `dotnet`. Um `applicationRoot` explícito substitui a descoberta, útil para wrappers, NSSM/WinSW, serviços com executável em outra pasta, comandos ambíguos ou caminhos relativos.

Na pasta encontrada, procura `appsettings*.json`, `*.config` e `*.runtimeconfig.json`. Portanto, cobre `web.config`, `app.config`, **`MeuServico.exe.config`** e arquivos adicionais `.config`. Em deployments de .NET Framework, normalmente o arquivo efetivo do executável é `NomeDoExecutavel.exe.config`, não o `app.config` do projeto.

- Campos JSON usam caminhos como `Config/appsettings.json/Endpoints/Pricing`.
- XML inclui atributos e texto, com chaves estáveis: `Config/web.config/configuration/appSettings(1)/add(key=Endpoint)/@value`.
- `~elementOrder` preserva a ordem XML; arrays JSON são comparados por índice. Objetos JSON não dependem da ordem de propriedades.
- `/` dentro de um segmento é codificado como `~1`; `~` como `~0`. Por exemplo, o nome de arquivo relativo `config\extra.json` vira `config~1extra.json`.
- Comentários e trailing commas JSON são aceitos. Chaves JSON duplicadas ou que diferem apenas na capitalização não são suportadas como modelo portável entre PowerShell 5.1 e 7; padronize esses arquivos antes da auditoria.
- Referências XML `configSource` e `file` são seguidas dentro da raiz da aplicação, com detecção de ciclos. Referências externas à raiz são reportadas; não são lidas automaticamente. Seções cifradas não são descriptografadas e ficam inconclusivas.
- `configPatterns` acrescenta padrões; `recurseConfig: true` habilita busca em subpastas. Por padrão, não há recursão e o limite por arquivo é 2 MiB (`collection.maxConfigBytes`), com até 1000 arquivos descobertos (`collection.maxConfigFiles`). Junctions/symlinks encontrados na árvore são ignorados e sinalizados. Evite recursão em árvores grandes.
- `binaryFiles` é uma lista explícita de executáveis/DLLs relativos à raiz. Compara FileVersion, ProductVersion e SHA256. Alterações de build podem produzir divergências intencionais; use exceções restritas e justificadas.
- `allowNoConfig: true` permite componentes sem arquivos de configuração.
- Para tasks com vários actions ou que executem PowerShell/cmd, informe `applicationRoot`: a pasta do interpretador não é necessariamente a pasta da aplicação.

Os arquivos são comparados separadamente. O kit **não reconstrói o `IConfiguration` efetivo de uma aplicação .NET**, pois a ordem de providers pode ser customizada. Variáveis de ambiente da máquina são coletadas somente pela allowlist, variáveis do pool/serviço são evidência adicional. Argumentos, cofre de segredos, configuração remota e valores em memória não são resolvidos. Um health check ou adaptador próprio pode expor valores efetivos não secretos necessários.

## Manifesto e requisitos

`items[].id` é a chave lógica. `environments` no item sobrescreve propriedades de primeiro nível: objetos e arrays como `expected` ou `health` são **substituídos por inteiro**, não mesclados recursivamente. `enabled: false` exclui um item daquela coleta e dos requisitos.

Operadores disponíveis em `expected` e `platformExpected`:

| Operador | Uso |
|---|---|
| Equals | Igualdade exata e sensível ao tipo |
| OneOf | Um dos valores de um array |
| Exists | Pelo menos um campo corresponde ao caminho |
| Contains | Texto contém literal, sensível a maiúsculas |
| Regex | Expressão regular .NET |
| Min / Max | Limite numérico |
| MinVersion | Versão mínima no formato `System.Version`, sem sufixo prerelease |

`path` aceita wildcard PowerShell (`*`, `?`, `[...]`). Quando vários campos correspondem, **todos** precisam atender ao requisito. Se nenhum corresponde, o requisito falha, ou fica inconclusivo se a coleta estiver incompleta. Para um caminho com colchetes literais, use o escape de wildcard do PowerShell.

```json
{
  "id": "pricing-worker",
  "type": "Service",
  "name": "Pricing.Worker",
  "expected": [
    {"path": "Service/State", "operator": "Equals", "value": "Running"},
    {"path": "Service/StartName", "operator": "Equals", "value": "CORP\\svc-pricing"}
  ]
}
```

As regras de estado desejado usam **valores reais do ambiente**, antes de qualquer de/para. Assim, um servidor PRD apontando por engano para um endpoint de DEV pode falhar mesmo se os dois snapshots tiverem o mesmo valor. Configure requisitos explícitos para endpoints, contas e certificados críticos.

Tasks normalmente ficam `Ready`, e não `Running`. Não exija execução contínua para um job periódico. `LastTaskResult = 0` é só um exemplo: ajuste para os códigos e o histórico esperado; tasks nunca executadas e tarefas em execução possuem outros resultados legítimos. O resultado da última execução não demonstra que todos os ciclos anteriores foram bem-sucedidos.

O inventário detalhado de softwares/features está em `_platform`. Requisitos de software podem usar o padrão `Software/Registry64/Nome do Produto/*/DisplayVersion`. Para frameworks, o exemplo testa `Release >= 528040` (.NET Framework 4.8 ou superior) e presença dos runtimes .NET 8. Isso não atesta integridade da instalação nem compatibilidade de roll-forward de cada aplicação.

## De/paras e exceções

Cada mapping tem `item`, `path`, `mode`, `values`, `canonical` e `reason`. Os valores originais continuam no relatório; uma igualdade após normalização recebe `Accepted`.

```json
{
  "item": "orders-api",
  "path": "Config/appsettings.json/Endpoints/Pricing",
  "mode": "Exact",
  "values": {
    "DEV": "https://pricing-dev.internal",
    "OT": "https://pricing-ot.internal",
    "PRD": "https://pricing.internal"
  },
  "canonical": "<PRICING_ENDPOINT>",
  "reason": "Endpoint correspondente de cada ambiente"
}
```

`Exact` substitui um valor completo. `LiteralReplace` substitui trechos literais, útil para contas dentro de ACLs, diretórios ou SIDs dentro de SDDL. Não é regex; a substituição é case-sensitive. Regras são aplicadas na ordem declarada. Prefira escopos estreitos; evite mapear fragmentos genéricos como `dev` em todos os campos.

Para arquivos que mudam de nome, configure `configFileAliases` no item/ambiente: por exemplo, em DEV use `{ "appsettings.Development.json": "appsettings.environment.json" }` e em PRD `{ "appsettings.Production.json": "appsettings.environment.json" }`. Os atributos passam a usar o mesmo caminho lógico; o nome físico permanece em `ConfigSources/<nome lógico>` e pode receber seu próprio mapping. Não mapeie dois arquivos da mesma pasta para o mesmo nome lógico. Isso compara os overlays separadamente; não mescla os providers de configuração. Arquivos ausentes nunca são escondidos por uma regra de ignore.

`comparison.ignore` aceita `{ "item": "id", "path": "...", "reason": "..." }`. A exceção aparece como `Ignored` e não desabilita requisitos em `expected`. Para comparar certificados diferentes, mapeie thumbprints e atributos aprovados, mantendo `ValidNow` e `DaysRemaining` como requisitos independentes. O exemplo ignora diferenças de datas de emissão/expiração, mas exige pelo menos 30 dias restantes.

SDDL usa SIDs, que podem diferir entre domínios/contas locais. Adicione mapeamentos específicos para SIDs aprovados; o mapping de nomes de conta não normaliza SIDs automaticamente. ACL textual é evidência, não cálculo de acesso efetivo.

## Valores sensíveis

Por padrão, senhas, tokens, chaves, credenciais, connection strings e argumentos de execução reconhecidos são substituídos por `[REDACTED]`. Isso resulta em **Inconclusive**, pois dois valores mascarados não comprovam igualdade. Padrões adicionais em `security.sensitivePathRegex` ampliam a proteção; os padrões internos não são removidos.

Campos padrão de connection strings são expostos separadamente em `ConnectionDetails`: servidor, banco, usuário, criptografia e opções de pool/timeouts reconhecidas. Senhas e campos não permitidos não são expostos. O valor integral continua protegido. Connection strings com formatos de provider não reconhecidos podem ficar sem detalhes.

Para detectar igualdade/diferença de segredos sem exportar o conteúdo, forneça uma chave HMAC aleatória de pelo menos 32 bytes em Base64, pela variável **de processo** `DEPLOYMENT_AUDIT_HMAC_KEY`. Use a mesma chave para todos os snapshots da comparação. Distribua pelo mecanismo de segredo da sua equipe; não coloque o segredo no manifesto ou argumentos de linha de comando.

```powershell
# Gerar uma chave em uma sessão controlada; não imprimir, persistir nem registrar em transcript.
$bytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
$env:DEPLOYMENT_AUDIT_HMAC_KEY = [Convert]::ToBase64String($bytes)
[Array]::Clear($bytes, 0, $bytes.Length)

# Injetar EXATAMENTE esta mesma chave nas outras sessões via cofre/automação da equipe.
# Depois das extrações:
Remove-Item Env:\DEPLOYMENT_AUDIT_HMAC_KEY
```

Não gere uma nova chave em cada servidor: identificadores de chave diferentes tornam a comparação inconclusiva. HMAC não aceita de/para de valores secretos. Se segredos devem variar por ambiente, use exceção explícita com motivo ou compare referências não secretas ao cofre. Contas, caminhos, URLs e metadados continuam potencialmente internos; os JSONs/HTMLs devem permanecer sob os controles de acesso da equipe. Heurísticas não reconhecem todo nome possível de segredo: revise `sensitivePathRegex` antes de coletar configurações proprietárias.

## MQs e schedulers de outros produtos

`MSMQ` e `Task` têm coletores nativos. Quartz, Hangfire, RabbitMQ, IBM MQ, Control-M e outros produtos precisam de um adaptador que consulte sua API/banco/CLI autorizada e devolva o envelope em `examples/adapter-envelope.example.json`.

O tipo `JsonFile` lê uma exportação local. `HttpJson` faz GET de um endpoint que já devolva **o contrato do kit**; não aponta diretamente para uma API nativa de RabbitMQ ou Hangfire. Os exemplos estão desabilitados para não inventar conectividade ou estado.

O adaptador deve informar `schemaVersion`, `capturedAtUtc`, `complete` e `fields`. Use mapas com IDs lógicos estáveis, não arrays em ordem aleatória. Os campos ficam sob `Adapter/Fields/...`. Exponha, por exemplo, cron/timezone/misfire de jobs, durable/type/bindings de filas, consumidores, permissões, autenticação configurada e versão do broker. Nunca inclua conteúdo de mensagens ou credenciais.

`maxAgeMinutes` limita a idade da evidência; exports antigos ou incompletos ficam inconclusivos. HTTP remoto exige HTTPS e valida o certificado normalmente; localhost admite HTTP. Pode usar `useDefaultCredentials` ou token Bearer na variável indicada por `bearerTokenEnvironmentVariable`. Não há bypass de TLS nem redirecionamentos automáticos. O coletor não executa scripts arbitrários do manifesto.

## Leitura dos resultados e automação

| Status | Interpretação |
|---|---|
| Drift | Diferença entre snapshots após mappings |
| Fail | Requisito não atendido, inclusive item obrigatório ausente |
| Inconclusive | Falta de evidência, coleta parcial, segredo mascarado ou snapshot fora da janela |
| Accepted | Diferença original coberta por de/para |
| Equal / Pass | Campo igual / requisito atendido |
| Ignored | Exceção explícita e justificada |
| Informational | Métrica de execução, como PID, última execução e contagem de mensagens |

Métricas informativas podem ser verificadas por `expected`; elas apenas não causam drift automaticamente. Dois serviços parados podem ter campos `Equal`, mas falham independentemente se o manifesto exige `Running`.

O comparador, por padrão, trata snapshots mais antigos que 24 horas como inconclusivos. Ajuste `comparison.maxSnapshotAgeHours` se estiver comparando históricos. Ele não sabe se os servidores foram alterados depois da coleta. Snapshots com manifests diferentes também são sinalizados. O manifesto passado ao comparador determina os requisitos atuais; mantenha-o versionado junto aos snapshots.

Exit codes:

- `0`: sem falhas, drift ou inconclusivos no comparador. Na exportação significa que os coletores terminaram sem erro/parcial; não significa conformidade.
- `2`: pelo menos um `Fail` ou `Drift` no comparador.
- `3`: evidência inconclusiva, sem falha/drift de maior prioridade; na exportação, coleta parcial.
- `4`: erro de entrada/execução que impediu a operação.

Para muitos servidores, execute por papel equivalente (`api01` DEV contra `api01` OT; workers contra workers), usando um manifesto por papel/grupo. Não há agregação automática de farm nem distinção entre deployment ausente e responsabilidade de outro nó. O kit não usa WinRM; pode ser invocado pelo mecanismo remoto/CI que sua equipe já autoriza.

## Limites importantes

- Igualdade de configuração não demonstra disponibilidade de negócio. Site/pool `Started` não comprova resposta HTTP; configure health checks. HTTP 200 só comprova o contrato do endpoint consultado.
- ACLs, SDDL e grupos não simulam token efetivo de uma conta nem resolvem toda herança de AD, nested groups, share permissions, GPO, impersonation, Kerberos/SPNs, delegação ou permissões em banco/broker remoto. Não é um atestado de “todos os permissionamentos”.
- Validade temporal do certificado não comprova cadeia confiável, revogação, hostname correto ou acesso real da conta à chave. O health check mantém a validação TLS do Windows; pode verificar esses aspectos no caminho acessado.
- Private key ACL cobre arquivos RSA CSP/CNG locais acessíveis; HSM, outros providers e chaves ECDSA requerem adaptação e são sinalizados.
- O inventário de programas cobre HKLM; não inclui instalações de outros usuários, aplicações portáveis, todos os drivers ou runtimes instalados fora das pastas padrão. Declare binários/diretórios ou adaptadores adicionais quando necessário.
- IIS coleta um conjunto selecionado de propriedades herdadas; não exporta toda a configuração efetiva da máquina. Virtual directories adicionais têm seus caminhos/usuários registrados, mas a varredura automática de arquivos ocorre na raiz da aplicação selecionada.
- Inventário de filas é local; MQs em cluster/remotos precisam de seleção/conector apropriado. Existência de fila e serviço iniciado não provam produção/consumo ponta a ponta.
- Snapshot não é transação atômica. Um deploy durante a coleta pode misturar instantes; execute fora da janela de mudança e refaça se houver inconsistência.
- Mensagens cruas de exceção do coletor não são exportadas para evitar vazamento de valores secretos. O JSON registra tipo/código e escopo da falha.

## Validação do kit

```powershell
powershell.exe -NoProfile -File .\tests\Test-DeploymentAudit.ps1
```

Os 26 testes cobrem mappings, requisitos independentes, null/ausência/tipos, falhas parciais, HMAC, redação, XML seguro, JSON com comentários, descoberta de arquivos, connection strings, timestamps, IDs duplicados e escape HTML. Foram executados em PowerShell 7 em Linux; os coletores dependentes de Windows não foram exercitados contra servidores reais nesta entrega.

Primeiro teste em DEV: selecione uma API, um serviço e uma task conhecidos, extraia, compare os valores com IIS Manager/Services/Task Scheduler e valide uma mudança controlada de requisito no manifesto. Verifique a cobertura de ACL/MSMQ/certificados e os nomes de campos do seu Windows antes de usar como gate de produção. Nenhum script de teste altera serviços ou arquivos de configuração do servidor.

## Referências técnicas

- IIS PowerShell: https://learn.microsoft.com/en-us/iis/manage/powershell/powershell-snap-in-using-the-task-based-cmdlets-of-the-iis-powershell-snap-in
- IIS process model: https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel
- Task Scheduler: https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/get-scheduledtask
- MSMQ queues / ACL: https://learn.microsoft.com/en-us/powershell/module/msmq/get-msmqqueue e https://learn.microsoft.com/en-us/powershell/module/msmq/get-msmqqueueacl
- Inventário sem Win32_Product: https://learn.microsoft.com/en-us/powershell/scripting/samples/working-with-software-installations
- .NET Framework Release: https://learn.microsoft.com/en-us/dotnet/framework/install/how-to-determine-which-versions-are-installed
- Providers de configuração ASP.NET Core: https://learn.microsoft.com/en-us/aspnet/core/fundamentals/configuration/
