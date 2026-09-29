# AEGIS Browser 0.1.0 — instalação e homologação preliminar

Este pacote é uma prévia técnica para instalação manual e testes controlados. Não é publicação em loja nem comprovação de eficácia contra phishing. Use um perfil de navegador separado e dados de teste sem informação pessoal ou corporativa.

## Instalação em Chrome ou Edge

1. Baixe [`aegis-browser-0.1.0-preview1.zip` na Release do GitHub](https://github.com/onecio/aegis-browser/releases/tag/v0.1.0-preview1) e confira o SHA-256 publicado junto ao pacote.
2. Extraia o ZIP em uma pasta estável. O diretório selecionado precisa conter `manifest.json` diretamente; não selecione a pasta pai.
3. Abra `chrome://extensions` (Chrome) ou `edge://extensions` (Edge), habilite **Modo do desenvolvedor** e selecione **Carregar sem compactação** / **Load unpacked**.
4. Selecione a pasta extraída. Abra as opções da extensão. Jev, proteção de webmail, navegação Web contínua e menu contextual começam desativados.
5. Recarregue uma página após habilitar uma nova permissão. Para remover a prévia, remova a extensão pela página de gerenciamento.

O pacote não é instalado ao abrir o ZIP. A instalação manual requer modo de desenvolvedor; políticas corporativas podem bloquear essa opção.

## Teste estrutural do DOM de Gmail ou Outlook

Use uma conta de teste e uma mensagem criada para esse fim, sem nomes reais, anexos pessoais, códigos de acesso ou links que levem a serviços de produção. Conceda apenas a permissão do provedor testado em **Opções → Analisar Gmail e Outlook Web**. A permissão cobre somente os domínios de webmail declarados; ela não libera valores de senha, cookies ou tokens.

1. Abra uma mensagem de teste e confirme apenas se AEGIS reconhece a superfície, apresenta cobertura e sinaliza a mensagem. Não copie o texto da mensagem para logs, tickets ou capturas compartilhadas.
2. Navegue entre mensagens e confirme que a análise acompanha a mensagem atual. Recarregue a aba e confira se a interface volta sem erro.
3. Desative a proteção do provedor e confirme que o conteúdo deixa de ser monitorado. Revogue também o acesso na página de detalhes da extensão e confira o estado de permissão ausente nas opções.
4. Registre somente navegador/versão, provedor, resultado de reconhecimento e cobertura, sem remetente, assunto, corpo, URL completa ou captura da caixa de entrada.

Gmail e Outlook alteram seus seletores com frequência. O teste automatizado deste repositório usa fixtures sintéticas; até concluir este roteiro em uma conta de teste consentida, a adaptação ao DOM real permanece **não homologada**.

Para repetir a análise do DOM de uma página pública real, execute `npm run test:live-dom`. Esse teste isolado acessa a página pública da IANA sobre domínios reservados em Chrome e Edge com perfis temporários, valida somente status HTTP e estrutura de título/links e aciona a análise da extensão. Não coleta nem registra texto ou destinos da página; não valida o DOM autenticado de webmail. Para testar outro pacote já extraído, defina `AEGIS_EXTENSION_PATH` com o diretório que contém seu `manifest.json` e execute `node scripts/smoke-live-dom.mjs`.

## Permissões opcionais e menu contextual

Os smoke tests em Chrome e Edge clicam no controle real da extensão, confirmam a concessão/revogação de `contextMenus` e verificam que o service worker consegue registrar o item. Eles não selecionam o item no menu nativo do sistema. Concessões de origem para Gmail/Outlook e acesso amplo à Web dependem do prompt de hosts do navegador e precisam de confirmação manual no perfil de teste.

1. Em Opções, habilite **Analisar links pelo menu contextual** e aceite a solicitação de `contextMenus` do navegador.
2. Em uma página de teste, clique com o botão direito sobre um link. Confirme a presença de **Analisar link com AEGIS** e selecione-a.
3. Confirme que AEGIS mostra a análise sem navegar para o destino. Repita com um link benigno de teste.
4. Desative a opção: o item deve desaparecer. Revogue `contextMenus` pela tela de detalhes do navegador e confirme que a extensão não mantém a opção operacional.
5. Teste separadamente **Análise contínua da Web** somente em perfil descartável: essa permissão pode permitir leitura de páginas HTTP/HTTPS visitadas. Desative-a e revogue o acesso depois.

## Configuração do Jev pelo gateway

A chave TypeSafe pertence ao **servidor gateway**. Não a cole no campo de token do gateway da extensão. O gateway exige issuer e JWKS HTTPS reais, audiência, escopo, tenant permitido, origem exata da extensão e token OIDC emitido pelo provedor da organização. A prévia não inclui login OIDC; o operador precisa emitir esse token fora da extensão.

O endpoint TypeSafe usado pelo projeto é `https://api.typesafe.ai/v1/systemone`; a [API oficial](https://docs.typesafe.ai/api.md) espera a chave em `Authorization: Bearer <API_KEY>`. O gateway injeta esse cabeçalho do lado servidor. No modo BYOK, a própria extensão faz essa chamada HTTPS usando a chave da sessão.

1. Implante o serviço atrás de HTTPS confiável e configure no ambiente de execução os valores reais de `AEGIS_GATEWAY_ISSUER`, `AEGIS_GATEWAY_JWKS_URL`, `AEGIS_GATEWAY_AUDIENCE`, `AEGIS_GATEWAY_REQUIRED_SCOPE`, `AEGIS_GATEWAY_ALLOWED_TENANTS` e `AEGIS_GATEWAY_ALLOWED_ORIGINS`.
2. Consulte `chrome://extensions` ou `edge://extensions` e use a origem exata `chrome-extension://<id>` no allowlist. A ID pode variar entre Chrome, Edge e pastas de instalação. Não use CORS `*`.
3. Cadastre `TYPESAFE_API_KEY` no gerenciador de segredos do host/serviço. Para uma sessão local descartável do PowerShell, sem gravar a chave no histórico:

   ```powershell
   $secureKey = Read-Host 'TypeSafe API key' -AsSecureString
   $env:TYPESAFE_API_KEY = [System.Net.NetworkCredential]::new('', $secureKey).Password
   npm run gateway
   ```

   O valor fica em texto claro no ambiente do processo enquanto o gateway estiver ativo. Em serviço persistente, use o secret manager do host. `gateway/.env.example` é apenas referência e não é carregado automaticamente pelo Node.

4. Nas opções da extensão, selecione **AEGIS Secure Gateway**, informe somente a origem HTTPS, por exemplo `https://gateway.sua-organizacao.example`, e salve. Obtenha do operador um token OIDC válido para audiência, tenant e escopo configurados; informe-o em **Token de acesso temporário** e salve nesta sessão.
5. Ative **Jev**, aceite a permissão de host do gateway e selecione **Testar conexão**. O teste usa estado sintético. `Conexão validada` confirma o caminho da API; falha não desativa a análise local.

Não exponha `TYPESAFE_API_KEY`, token OIDC, payload de requisição ou cabeçalho Authorization em capturas e logs. A origem configurada deve ser HTTPS; o servidor local padrão em HTTP/127.0.0.1 não serve como destino da extensão.

## Testes Jev: gateway, BYOK e modo local

| Extensão | Gateway/credencial | Resultado que deve ser observado |
|---|---|---|
| Jev ON, modo Gateway | Gateway HTTPS ativo, chave TypeSafe no secret manager e token OIDC válido | Teste sintético conecta; análises elegíveis podem enviar features minimizadas. Confirme `Conexão validada` e a indicação de Jev no painel. |
| Jev ON, modo Gateway | Gateway parado ou inacessível | Teste de conexão falha; a análise local continua. O painel deve indicar indisponibilidade do Jev. O gateway é fail-closed e não inicia sem a chave de servidor. |
| Jev OFF, modo Gateway | Gateway ativo, mesmo com chave instalada | Análise local funciona e não deve haver POST `/v1/systemone`. Revise apenas contagem e destino no inspetor de rede do service worker; não exporte cabeçalhos ou corpos. |
| Jev ON, modo BYOK | Gateway dispensado; chave TypeSafe inserida no campo **Minha TypeSafe API Key** e salva na sessão | Teste sintético acessa diretamente `api.typesafe.ai`; a chave fica temporária no perfil e não deve ser compartilhada. |
| Jev OFF | Gateway parado e sem chave BYOK | Somente regras locais; zero chamada Jev. Desativar Jev remove segredos de sessão. |

Para testar indisponibilidade, pare o gateway de teste ou bloqueie temporariamente sua origem. Não apague nem invalide uma chave de produção. Para interromper o tráfego, desligue Jev nas opções e salve.

## Limites desta prévia

CI, CodeQL e Gitleaks foram executados remotamente; o CodeQL atual não apresenta alertas abertos. A CI também valida o ZIP extraído em Chrome e Edge contra a página pública da IANA. Duas revisões independentes de código foram concluídas e as correções identificadas foram verificadas. Esses resultados não substituem a confirmação manual dos prompts de hosts, o clique no menu nativo, o DOM autenticado de Gmail/Outlook, credenciais de homologação reais, uma auditoria externa, corpus consentido ou análise de falsos positivos/negativos. Não use esta prévia como única proteção de uma conta ou organização.
