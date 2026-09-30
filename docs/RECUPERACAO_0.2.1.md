# AEGIS Browser 0.2.1 — candidata local de recuperação

Data: 29/09/2026. Base Git: 55894c9dde23507b73dfdb9d81e3a9600966f9bb.
As alterações desta candidata são locais e ainda não constituem um commit ou uma publicação remota.
Estado: candidata para homologação; eficácia em contas reais e inferência JEV real não comprovadas.

## Correções e evidências

| Defeito | Correção | Evidência disponível |
| --- | --- | --- |
| CSP bloqueando estilos nos documentos da extensão | Classes CSS e arquivo content.css registrado/injetado; avisos usam CSSStyleSheet construída | Regressão de atributos inline e auditoria MV3; teste DOM dos avisos |
| Unsubscribe tratado como indício de spam | Controle de envio em massa vira contexto com severidade zero; termos isolados não produzem badge | Fixture Gmail e regressão de sinalização |
| Rolagem limitada aos primeiros itens | Seleção incremental por janela visível, evento scroll e debounce de 160 ms | Teste DOM com 60 linhas, risco na linha 40 |
| Resultado aplicado a linha reciclada | Comparação de elemento, payload, rota e geração antes de decorar | Testes de nó reciclado, A→B→A e resposta atrasada |
| Caixa de entrada ignorada com mensagem aberta | Triagem da caixa e análise aberta executadas conjuntamente | Alteração de fluxo; combinação em Outlook real ainda pendente |
| Poluição visual | Badges pequenos, sem contorno da linha inteira ou fundo dos links | Imagens sanitizadas e teste de estilo/foco |
| Chave salva antes de salvar modo JEV | Fluxo solicita permissão e salva modo/configuração antes de registrar credencial | Revisão do fluxo e teste de credencial de sessão em Chrome isolado |
| Enriquecimento atrasando triagem local | Resultado local primeiro; enriquecimento posterior e limite global de duas chamadas | Implementação e regressões locais; latência com provedor real pendente |
| Mensagens administrativas acessíveis a content script | UI confiável exigida para configurações, credenciais e consulta arbitrária de análises | Regressão de remetentes/origem |
| Resultado antigo governando página nova | analysisId, URL e invalidação de decisões/guardas por mudanças de contexto | Revisão independente e regressões DOM |
| ClickFix invisível na análise automática | Aviso passivo sem roubar foco; dispensa escopada por 10 minutos | DOM Chrome, captura sanitizada e revisão |
| Gateway rejeitando origem da extensão | Validação do protocolo/ID exato em lugar de URL.origin opaca | Regressão inicialmente falhou; 11 testes do gateway passaram |

Os relatos originais em Gmail/Outlook pessoais não foram reproduzidos no DOM autenticado nesta execução. Os testes acima usam conteúdo controlado e perfis isolados. As causas demonstradas nesses testes não provam, por si só, a causa de todos os sintomas no ambiente pessoal.

## Testes e limites das métricas

- ESLint, auditoria do bundle e auditoria de padrões de segredos: aprovados. npm audit: zero vulnerabilidades reportadas.
- Suíte Node final: 83/83 testes passaram; inclui regressões de origem do gateway e ClickFix em e-mail.
- DOM Chrome: caixa limpa, rolagem profunda, badge localizado, preservação de foco, A→B→A, resultado atrasado, limpeza ao desativar e aviso passivo ClickFix passaram. Transporte simulado.
- Chrome MV3 isolado: instalação, permissões de menu contextual, cadastro/removal de menu, análise offline sem JEV, zero chamadas HTTP do worker, proteções de links/formulários, atualização por mutação, painel e privacidade passaram.
- A exibição de julgamentos JEV usa resposta controlada; não demonstra inferência real.
- Edge: processo do perfil isolado encerra com código 0 antes da conexão Puppeteer. Não houve validação concluída desta candidata no Edge.
- Microbenchmark Chrome 154.0.8037.58: extração+análise aberta p95 Gmail 0,20 ms, Outlook 0,14 ms, genérico 0,09 ms; triagem local de 20 linhas p95 Gmail 1,50 ms, Outlook 1,49 ms, genérico 0,87 ms; página 0,17 ms. São operações sintéticas, não latência de ponta a ponta. Debounce separado: 160 ms. A tarefa do próprio benchmark executa várias repetições no mesmo lote e não comprova ausência de long tasks no produto.
- Precisão, recall e falsos positivos em corpus representativo: não medidos. Metas de 98%, 1% e 90% não estão homologadas.
- CI/CodeQL remoto desta candidata: não executado. Resultados remotos anteriores não cobrem estas alterações locais.

## Instalar sem duas versões ativas

1. Preserve a pasta da versão anterior e suas preferências para rollback. Não exporte credenciais para arquivos.
2. Extraia aegis-browser-0.2.1-recovery.zip em uma pasta nova e permanente.
3. Em chrome://extensions, localize a instalação AEGIS existente. Se sua pasta atual é conhecida, substitua seus arquivos pela candidata e clique Recarregar; confirme versão 0.2.1.
4. Se optar por Carregar sem compactação na nova pasta, desative a instalação anterior primeiro. Confira que somente uma AEGIS está habilitada. Um novo caminho pode gerar outro ID, exigindo ajuste da origem permitida no gateway e novas permissões.
5. Recarregue as abas de teste para retirar scripts da versão anterior. Ative a proteção necessária nas opções e aceite suas permissões.
6. Teste primeiro com uma conta de homologação consentida. Não envie nem abra mensagens privadas automaticamente.
7. Para rollback, desative a candidata e reative/recarregue a pasta preservada. Recarregue novamente as abas.

As preferências de proteção permanecem em storage.local. Conforme o prompt mais recente, BYOK/token ficam somente em storage.session, sem migração silenciosa para armazenamento permanente. Encerrar a sessão do navegador exige nova credencial. Desativar JEV apaga a credencial de sessão. Uma chave eventualmente persistida por versão antiga não é importada por esta candidata; avalie removê-la e rotacioná-la no provedor.

## JEV direto, gateway e desativado

Contrato conferido em https://docs.typesafe.ai/api: POST /v1/systemone, Bearer, state/model/questions e respostas tipadas.

### BYOK na extensão

Em Opções, selecione BYOK, habilite JEV, informe a chave TypeSafe no campo próprio e clique Salvar chave. Aceite somente a permissão api.typesafe.ai solicitada pelo fluxo. Clique Testar conexão: ele envia estado sintético mínimo e valida uma inferência tipada. A presença da chave ou o checkbox não comprovam uma conexão. O último teste é registrado na sessão com horário, modo e resultado.

### API pelo gateway

No servidor, configure TYPESAFE_API_KEY como segredo no ambiente do processo. Nunca insira a chave do provedor no campo de token do gateway da extensão. Configure AEGIS_GATEWAY_ISSUER, AEGIS_GATEWAY_JWKS_URL, AEGIS_GATEWAY_AUDIENCE, AEGIS_GATEWAY_REQUIRED_SCOPE, tenants autorizados e AEGIS_GATEWAY_ALLOWED_ORIGINS=chrome-extension://ID_REAL_DA_EXTENSAO. Execute npm run gateway atrás de HTTPS confiável. A configuração completa consta de gateway/.env.example e gateway/README.md.

Na extensão, selecione Gateway, informe a URL HTTPS base, habilite JEV e salve um token OIDC válido para audiência/escopo/tenant configurados. Testar conexão valida inferência; GET /health demonstra apenas disponibilidade operacional. OIDC, TLS e segredos reais ainda dependem do ambiente de homologação e não foram provisionados nesta execução.

### Comparações necessárias

1. JEV direto: BYOK ativo e teste de inferência aprovado; mesmo corpus rotulado.
2. JEV via gateway: gateway ativo, OIDC válido e inferência aprovada; mesmo corpus.
3. JEV desligado na extensão: regras locais, sem chamada remota.
4. Gateway indisponível/JEV upstream indisponível com extensão habilitada: observar erro explícito e manter resultado local; indisponibilidade não significa conteúdo seguro.

Não há métricas comparativas reais nesta entrega. Não exponha a chave em mensagens, capturas, logs ou repositórios.

## Revisão, distribuição e pendências

Uma revisão independente apontou falhas de leitura entre abas, cache A→B→A, decisões atrasadas, tentativas após erro, aviso ClickFix e invalidações concorrentes. As correções foram implementadas; a última revisão dirigida exigiu limpar o aviso passivo em hash/popstate, também corrigido.

Ainda faltam DOM autenticado Gmail/Outlook acompanhado pelo usuário, pesquisa real/ads/wrappers em todas as variantes, corpus consentido e avaliação separada, comparação com JEV real, medições completas de desempenho e acessibilidade, operacionalização HTTPS/OIDC do gateway e CI/CodeQL remoto da candidata. O controlador da sessão pessoal foi interrompido por aprovação automática porque não conseguiu determinar a URL do Chrome com confiança; não foi tratado como autorização para contornar esse controle.

Nome sugerido: AEGIS Browser — Guardião de E-mail e Navegação. Aegis, ou égide, remete ao escudo/proteção da tradição clássica. O nome mantém a identidade já existente e não representa certificação de segurança.

## Identificação do pacote

Pacote: aegis-browser-0.2.1-recovery.zip
SHA-256: 171C0838D9FD388DD75878C652671CA4B20A80126CEF4CF2B1A2F8A799A8EC62

