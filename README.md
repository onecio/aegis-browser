# AEGIS Browser

Nome sugerido para a extensão: **AEGIS Browser**; nome sugerido para o repositório: **`aegis-browser`**. “AEGIS” expande para **Adaptive Email & Web Guardian with Intelligent Security** e remete à égide, um escudo protetor: descreve a função de guardião para e-mail e navegação, mantendo um nome curto para a interface. A versão 0.1.0 é uma prévia de instalação manual para homologação, não uma extensão publicada em loja.

Extensão MV3 para Chromium, com análise local de URLs, domínios, mensagens e formulários. Jev é opcional. O modo inicial é AEGIS Local; proteção de webmail e acesso contínuo à Web exigem permissões concedidas pelo usuário.

## Desenvolvimento local

Requisitos: Node.js 22.13 ou superior, npm, Chrome e Microsoft Edge instalados. O pacote de automação usa os binários locais e não baixa navegadores.

```powershell
npm ci
npm run validate
```

O comando `npm run validate` executa ESLint, testes unitários e de integração do gateway, compara duas builds recursivas do pacote, gera o SBOM, instala a extensão em perfis temporários de Chrome e Edge para testar o worker, popup, opções, alertas e privacidade, audita o bundle e consulta vulnerabilidades conhecidas das dependências. `npm run verify:repro` executa a verificação de duas builds; o SBOM fica fora do hash porque contém metadados de geração. `npm run build` recompila o pacote e também gera o SBOM. Se os navegadores não estiverem nos caminhos padrão, defina `AEGIS_CHROME_PATH` e `AEGIS_EDGE_PATH`.

`npm run validate` também verifica padrões de credenciais no código executável fora das fixtures de teste e gera `dist/aegis.spdx.json` a partir das dependências instaladas. O bundle distribuído tem uma auditoria própria, que inclui os arquivos JavaScript empacotados. O workflow `.github/workflows/ci.yml` executa a validação em Windows, publica o SBOM como artefato e executa Gitleaks 8.30.1 em um job Ubuntu separado, com histórico completo e hash SHA-256 fixado antes da execução. `.github/workflows/codeql.yml` configura SAST com CodeQL; em repositório privado, a variável `CODEQL_ENABLED=true` só deve ser definida quando o code scanning estiver disponível. Esse workflow usa Advanced Setup e não deve concorrer com o CodeQL Default Setup. Os workflows ainda não foram executados no GitHub. A varredura local usa padrões de alta entropia e não percorre o histórico Git; o SBOM não é assinado.

Os textos próprios da interface, dos avisos e dos sinais locais usam o i18n nativo do Chromium e o catálogo `extension/_locales/pt_BR/messages.json`. A instalação atual oferece pt-BR; a estrutura permite acrescentar os catálogos `en_US` e `es`, que ainda não têm traduções distribuídas. Um teste verifica as chaves do manifesto, das telas e dos sinais conhecidos.

Carregue `dist/` como extensão descompactada em `chrome://extensions` ou `edge://extensions`, com o modo de desenvolvedor ativo, para revisar a interface manualmente. Recarregue a extensão após uma nova build.

O roteiro de instalação, permissões, menu contextual, testes estruturais do DOM e configuração segura do Jev está em [`docs/GUIA_INSTALACAO_HOMOLOGACAO.md`](docs/GUIA_INSTALACAO_HOMOLOGACAO.md). A distribuição exige carregar a pasta que contém `manifest.json`; abrir o ZIP não instala a extensão.

Na validação integral local de 29/09/2026, ESLint, 70 testes automatizados, build reproduzível, smoke tests MV3 em Chrome e Edge, auditorias do bundle e de segredos passaram; `npm audit` reportou zero vulnerabilidades e o SBOM SPDX foi gerado. A verificação comparou duas builds consecutivas e produziu o mesmo hash para os 14 arquivos do pacote da extensão: `6790a9677a201b9f05fb75ea297d9663f2ee78c75ce8dad40687f78847158da4`, excluindo o SBOM que contém metadados de geração. Em uma validação separada de 28/09, `npm ci` e Gitleaks 8.30.1 também passaram. Os smoke tests usam páginas e fixtures sintéticas servidas apenas em `127.0.0.1` e perfis temporários; confirmam o catálogo pt-BR nas telas e nos rótulos acessíveis do popup e dos avisos. Verificam os adaptadores, inclusive o rótulo pt-BR do corpo no Outlook e a extração limitada de nome, extensão e MIME de anexos sem baixar arquivos; também cobrem análise manual redigida sem abrir a URL, origem de sessão sem path/query, mutações SPA em `href`, substituição do elemento principal e alteração textual sem mudança de atributo, destaque e restauração de links, bloqueios de clique/formulário, alerta acessível com descrição do destino, retorno do foco e confirmação explícita, painel Jev, dashboard agregado, feedback sem conteúdo, exclusão local e decodificação local de um QR real. Testes de revogação cobrem a exclusão seletiva das análises por origem, a preservação de credenciais com acesso ainda concedido e a remoção do segredo Jev mesmo quando falham as limpezas auxiliares de análises ou campanhas. O fluxo Jev OFF roda com o service worker emulado offline e confirma zero requisições HTTP/S. Os inventários sintéticos `docs/golden_seed.csv` e `docs/adversarial_seed.csv` cobrem os cenários planejados; o benchmark de extração e análise está em `docs/BENCHMARK_SYNTHETIC.md` e não mede o impacto em Gmail ou Outlook reais. `BarcodeDetector` não estava disponível nos dois navegadores testados; o fallback JS local passou. Uma varredura QR parcial ou indisponível reduz a cobertura do e-mail e preserva os achados dos QR já decodificados. Limites de corpo, links, anexos e URLs de QR são informados como cobertura parcial. Mensagens abertas apenas com imagem são reconhecidas para leitura local de QR. Calibração com corpus representativo, revisão independente e execução do workflow no repositório remoto ainda estão pendentes; consulte o Gate Review em `docs/FASE0_AEGIS.md`.

## Permissões

- **Analisar Gmail e Outlook Web:** solicita os domínios de e-mail suportados quando ativado. A triagem de caixa de entrada usa remetente, assunto, prévia e links visíveis; a mensagem aberta recebe análise aprofundada local.
- **Análise contínua da Web:** pede acesso a sites HTTP e HTTPS somente após ativação explícita. O usuário também pode analisar uma página manualmente com `activeTab`.
- **Menu contextual de links:** desligado por padrão. Ao ativá-lo, a extensão solicita `contextMenus` e adiciona “Analisar link com AEGIS”; a verificação é local e não abre o destino.
- **Jev:** começa desligado. A ativação solicita acesso somente ao host do provedor selecionado. Sem Jev, nenhuma análise é enviada a serviços externos.

A análise manual de URL não visita o endereço. A extensão não lê valores de campos de senha, cookies, histórico, clipboard ou tokens de sessão do navegador. Os scripts só são registrados após a concessão das permissões. A análise de conteúdo é uma medida auxiliar e não substitui as proteções do navegador.

## Jev e privacidade

`Strict` envia apenas features estruturadas. `Balanced` e `Enhanced` também podem enviar trechos limitados, após filtros de redação; texto arbitrário pode conter informação sensível que o filtro não reconheça. A interface descreve esse limite. Nenhum corpo integral ou caixa de entrada é enviado.

**BYOK:** selecione “Minha própria API Key”, ative Jev, salve as configurações e informe a chave na tela de opções. Ela fica em `chrome.storage.session`, não no pacote ou no content script. Desativar Jev remove as credenciais de sessão.

**Gateway:** é o modo recomendado na interface. Selecione a origem HTTPS e ative Jev; um administrador deve fornecer um token de acesso válido para o emissor OIDC, o tenant e o escopo configurados no gateway. O campo de token é temporário e permanece apenas na sessão da extensão. Esta versão não contém uma tela de autenticação OIDC interativa.

## Métricas e feedback locais

O dashboard exibe contagens agregadas dos últimos 30 dias e mantém no dispositivo até 90 dias de registros diários. O feedback aceita apenas categorias predefinidas para a análise ativa e grava contadores locais; não armazena conteúdo, remetente, domínio ou identificador da análise, não altera decisões e não envia dados. O usuário pode apagar as métricas pela interface.

## Modelo organizacional gerenciado

Um administrador pode distribuir `organizationDetectionModel` pela política gerenciada do navegador. A versão 1 contém apenas identificador, versão e a base tipada de marcas/domínios; não aceita código, expressões ou ajustes livres de risco. A política substitui a base local e é aplicada no dispositivo. Um pacote inválido desativa a base organizacional, mantendo as regras locais. O modelo não coleta nem transmite eventos dos usuários. A validação da política em navegador corporativo permanece no Gate Review.

## Gateway

O servidor de referência está em `gateway/server.js`. Ele exige token JWT validado contra JWKS, emissor, audiência, escopo e tenant autorizados; aplica CORS por origem exata, limite por usuário, tamanho de payload, schema allowlist, timeout e retry limitado. Reconstrói perguntas permitidas no servidor, usa a chave TypeSafe somente do ambiente do servidor e não registra payloads ou credenciais.

Configure as variáveis indicadas em `gateway/.env.example` no ambiente de execução ou em um gerenciador de secrets. Esse arquivo contém somente valores ilustrativos. O servidor escuta em `127.0.0.1` por padrão. Uma implantação remota deve restringir a rede e terminar TLS num proxy confiável. O limitador é local ao processo; uma implantação com várias instâncias requer rate limiting distribuído.

Para o token aceito pelo gateway, registre o identificador exato da extensão como origem permitida e configure um tenant e um escopo explícitos. IDs de extensões descompactadas podem variar entre instalações; não habilite CORS com `*`.

## Base Unicode

O detector de confusáveis usa o perfil `MA` de `confusables.txt`, versão Unicode Security Mechanisms 18.0.0, empacotado localmente. A tabela e a licença Unicode estão em `data/unicode/`; a geração do mapa é reproduzível por `npm run update:unicode` e o script exige revisão explícita se a versão mudar.

## Limites desta versão

- Gmail e Outlook mudam a estrutura do DOM; adaptadores separados retornam um formato normalizado, mas ainda usam seletores heurísticos e precisam de regressão contínua com DOM real. Ausência de cobertura adequada retorna `UNKNOWN`.
- A extensão não verifica SPF, DKIM ou DMARC e não confirma que o domínio pertence a uma marca.
- Mensagens sem corpo visível, link, QR decodificado ou metadados de anexo ficam `UNKNOWN`, mesmo quando remetente e assunto foram extraídos. Esta versão não aplica OCR a imagens.
- Os limiares são regras iniciais e não foram calibrados com corpus representativo. O `golden_seed.csv` é sintético e não representa taxa de erro de produção.
- A leitura local de QR cobre até 12 imagens carregadas (4 MP por imagem e 12 MP no total), usa `BarcodeDetector` quando disponível e o fallback local jsQR quando necessário. No fallback, cada imagem é reduzida a no máximo 512 px por lado e o total não passa de 1.048.576 pixels. O prazo de 2 s é verificado entre chamadas; uma decodificação síncrona em andamento não pode ser interrompida. Imagens com canvas bloqueado por CORS e mensagens acima dos limites ficam com cobertura parcial; o destino decodificado nunca é aberto. Browser-in-the-Browser é apenas um sinal estrutural contextual, sem elevação autônoma do risco. O contrato de feed de reputação permanece desativado e sem provedor configurado. ClickFix permanece fora do escopo.
- O gateway é um serviço de referência; identidade, tenancy, TLS e limites distribuídos dependem da configuração operacional.
- O smoke automatizado confirma instalação, worker, popup, análise local de página sintética, fixtures com seletores dos adaptadores, aviso pré-credencial, destaque/tooltip de link, bloqueios de link/formulário, navegação por teclado no aviso, painel Jev, dashboard agregado, feedback local sem conteúdo, rejeição de feedback obsoleto, exclusão das métricas e ausência do valor de senha armazenado. As fixtures não substituem a adaptação DOM real de Gmail/Outlook; o fluxo interativo de concessão/revogação e a acessibilidade manual do painel ainda exigem validação por provedor. [Guia de sideload do Edge](https://learn.microsoft.com/en-us/microsoft-edge/extensions/getting-started/extension-sideloading).

Esta prévia pode ser distribuída para testes controlados a pedido do responsável pelo projeto; essa distribuição não declara eficácia nem homologação de produção. Os gates restantes e o escopo da validação estão listados em `docs/FASE0_AEGIS.md` e no guia de homologação.
