# AEGIS Browser 0.3.0 — evolução e evidências

Candidata experimental de 30/09/2026. Nome: **AEGIS Browser**, Adaptive Email & Web Guardian with Intelligent Security. A referência à égide representa proteção e vigilância. Esta versão pode ser instalada manualmente; não constitui homologação de eficácia ou publicação em loja.

## Funcionamento por superfície

| Superfície | Unidade analisada | Sinalização |
| --- | --- | --- |
| Caixa de entrada Gmail/Outlook | Remetente, assunto e prévia visível de cada item | Marcador discreto por item, condicionado a evidência local material. Controles de descadastro e palavras isoladas não classificam spam. |
| Mensagem aberta/conversa | Corpo visível, remetente, links, metadados de anexos e QR limitado de cada mensagem | Evidências permanecem vinculadas à mensagem. Uma mensagem não empresta evidência à vizinha. |
| Google/Bing | Cada resultado e seu destino visível | Destinos encapsulados pelo buscador são decodificados localmente. Destino não resolvido indica cobertura insuficiente. O destino não é visitado. |
| Página comum | Região visível com contexto adjacente, links e formulários dessa região | A análise acompanha a rolagem. Conteúdo fora da janela ou dos limites fica explicitamente fora da cobertura. |

Vermelho requer evidência local forte e relacionada à mesma unidade. Exemplos incluem link enganoso combinado com pedido ativo de credenciais, coleta insegura de senha ou instruções convergentes de ClickFix. Amarelo indica revisão, não uma confirmação de spam ou phishing. Marcadores não modificam o endereço do link nem bloqueiam toda uma linha da caixa de entrada. O painel também apresenta contexto que não merece marcação.

ClickFix exige instruções operativas para abrir uma ferramenta do sistema e colar/executar comandos, ou um padrão de execução remota associado a falsa correção/verificação. Relatos educativos com advertência específica são tratados separadamente; a palavra “educativo” não neutraliza instruções operativas adicionais.

As marcações acompanham mutações e rolagem, com filas limitadas, versões por item e descarte de respostas obsoletas. **Ignorar por 10 minutos** vale somente para o item, conteúdo e evidências atuais; uma alteração relevante invalida a exceção.

## Controle operacional e privacidade

- As opções de proteção e privacidade persistem no perfil. Proteção contínua permanece habilitada até desativação ou revogação das permissões.
- A análise manual é pontual. Não habilita proteção contínua. Pausar uma aba remove sinalizações e guardas; salvar JEV/privacidade preserva essa pausa.
- Proteção Web e proteção de e-mail têm autorizações distintas. Os hosts Outlook Office, Office365, Live e Cloud Microsoft são reconhecidos.
- A chave BYOK e o token do gateway ficam em `chrome.storage.session`, acessível a contextos confiáveis da extensão. Sobrevivem à suspensão do service worker, mas não ao encerramento da sessão do navegador. Desativar JEV ou revogar o host remove a credencial. Essa escolha segue o requisito de privacidade do prompt de recuperação mais recente.
- STRICT envia somente features. BALANCED/ENHANCED exigem consentimento explícito para trechos redigidos; os filtros não garantem anonimização completa.
- A prévia de envio usa um exemplo sintético e o mesmo filtro do caminho de inferência; não extrai conteúdo de uma aba.
- Não são lidos valores de senha, cookies, histórico, clipboard ou tokens de sessão do navegador. A extensão não abre automaticamente destinos suspeitos.
- O diagnóstico distingue credencial registrada, inferência validada, teste sintético, fila e indisponibilidade. Teste aprovado refere-se àquele momento.
- Popup, opções e painel usam tema claro/escuro do sistema, contraste e foco de teclado explícito, respeitando a preferência de movimento reduzido.

## JEV e gateway

O JEV fornece julgamentos tipados em 12 dimensões. Política, permissões, limiares, efeitos e fallback permanecem em código determinístico. JEV não reduz risco local nem produz vermelho autonomamente.

A API usa o [contrato oficial TypeSafe](https://docs.typesafe.ai/api). O validador verifica tipos, campos, probabilidades, classificação, escalas e legendas. A correção desta versão tolera somente a discrepância matemática causada pelo arredondamento independente do escore e de suas probabilidades. Respostas incompatíveis são rejeitadas e a análise local continua.

O worker limita inferências a duas simultâneas e oito pendentes, com cache, cancelamento e invalidação após troca de configuração/credencial. O gateway limita concorrência global, autentica JWT com expiração, emissor, audiência, tenant e escopo; aceita origens exatas e schemas permitidos, com limites de corpo, prazo e retry limitado. O entrypoint foi corrigido para Windows.

### Configurar BYOK

1. Abra **Opções → Minha própria API Key** e mantenha STRICT inicialmente.
2. Informe a chave no campo TypeSafe e selecione **Salvar nesta sessão**. Esse fluxo ativa JEV e solicita somente o host do provedor.
3. Aceite a permissão no navegador e selecione **Testar conexão**. Um teste válido exibe o modelo devolvido.
4. Ative separadamente proteção de e-mail ou Web. Para analisar uma única página, use o popup.
5. Desative JEV nas opções para interromper chamadas e remover a credencial. Após fechar completamente o navegador, a próxima sessão exige inserir a chave novamente.

### Configurar gateway

O arquivo `gateway/.env.example` é referência; Node não o carrega automaticamente. Configure no ambiente do serviço os valores reais de issuer/JWKS HTTPS, audiência, escopo, tenants, origem exata da extensão e limites. A chave TypeSafe pertence ao servidor.

```powershell
$taskSecureKey = Read-Host 'TypeSafe API key' -AsSecureString
$env:TYPESAFE_API_KEY = [System.Net.NetworkCredential]::new('', $taskSecureKey).Password
npm run gateway
```

Em serviço persistente, forneça o segredo pelo gerenciador do host. O processo escuta localmente em HTTP/127.0.0.1 por padrão; para a extensão, publique uma origem HTTPS com certificado confiável e proxy configurado. Sem configuração válida o processo rejeita a inicialização. `GET /health` indica somente saúde do processo.

Na extensão, selecione **AEGIS Secure Gateway**, informe a origem HTTPS e salve o token OIDC temporário emitido para a audiência, tenant e escopo configurados. **Não cole a chave TypeSafe no campo de token do gateway.** Esta versão não contém login OIDC interativo.

| JEV na extensão | Caminho | Resultado esperado |
| --- | --- | --- |
| Ativo | BYOK válido; gateway dispensado | Teste e análises elegíveis usam diretamente TypeSafe. |
| Ativo | Gateway HTTPS ativo + token OIDC válido + chave no servidor | Gateway valida identidade e encaminha estado permitido. |
| Ativo | Gateway parado/token inválido/provedor indisponível | Diagnóstico factual e análise local preservada. |
| Inativo | Gateway ativo ou parado | Nenhuma inferência JEV; somente análise local. Credencial de sessão removida. |

## Evidências e seus limites

Arquivos gerados ficam em `release/evolution-0.3.0/`; replays tipados sintéticos estão em `tests/fixtures/`. Não contêm credenciais ou mensagens privadas.

| Verificação | Resultado registrado | Limite |
| --- | --- | --- |
| Regressão local | 44 casos; 14/14 vermelhos corretos; 14/14 casos altos cobertos | Corpus sintético pequeno, posteriormente usado no ajuste; não é holdout independente. |
| Falso alerta visível | 1/28 benignos = 3,57%; Wilson 95%: 0,63%–17,71% | Não satisfaz o gate de até 1% representativo; não mede contas reais. |
| JEV real | 24/24 respostas válidas após correção; modelo `jev-1.13.0` | 12 casos sintéticos em STRICT e ENHANCED; não mede população. |
| Ablation JEV | STRICT: zero mudanças visíveis; ENHANCED: quatro mudanças de estado semântico, zero mudanças visíveis | Nenhum ganho de precisão visível demonstrado neste subconjunto. |
| Latência JEV | p95 STRICT 762,2 ms; ENHANCED 283,8 ms | Inferência observada nessa execução; não inclui descoberta/renderização do navegador. |
| Gateway real | CLI iniciado; saúde 200; sem JWT 401; origem indevida 403; capacidade 503; uma inferência JEV válida | Identidade RS256/JWKS efêmera de teste. OIDC, TLS e operação produtivos não homologados. |
| JEV no MV3 | Uma inferência real pelo worker, HTTP 200; chave preservada após encerramento/reinício do worker; desligar removeu a chave e produziu zero nova chamada | Perfil temporário e cópia de ensaio com host do provedor previamente declarado. O manifesto distribuído não foi modificado; prompt nativo não validado por esse ensaio. |
| DOM dinâmico | Fixtures Gmail/Outlook/Google/Bing, conversa, reciclagem, rolagem e ClickFix após 31 mil caracteres aprovadas em Chrome | DOM sintético com transporte emulado; não substitui webmail autenticado. |
| Custo do monitor | Fixture longa: 2 ms local/4 ms total; nenhuma long task acima de 50 ms observada | Transporte emulado. Não comprova p95 descoberta/renderização até 300 ms em produção. |
| Renderização | Capturas sanitizadas, viewport compacto e DPR 2 | DPR não equivale a zoom nativo 200%; revisão de acessibilidade completa permanece pendente. |

A primeira execução JEV rejeitou 11/24 respostas devido ao arredondamento; o baseline foi preservado. Um marcador de revisão em exemplo benigno com texto de URL divergente permanece documentado; sua expectativa não foi alterada para melhorar artificialmente a métrica.

O controlador do Chrome pessoal não iniciou nesta sessão. Não foi examinada caixa postal privada nem atualizado automaticamente o perfil já instalado. A validação do DOM autenticado deve ser acompanhada em conta de teste consentida. Clique nativo no menu contextual, prompts nativos de hosts, OIDC real e gates representativos permanecem identificados separadamente.

## Instalação, reprodução e rollback

Extraia o ZIP 0.3.0 em uma pasta estável e selecione a pasta contendo diretamente `manifest.json` em **Carregar sem compactação**, nas extensões do Chrome/Edge. Se já utiliza `dist/`, selecione **Recarregar** após a build e recarregue as páginas de teste. Confira a versão exibida e o SHA-256 do pacote.

```powershell
npm ci
npm run validate
npm run evaluate:jev
npm run verify:jev-gateway
npm run verify:jev-extension
```

Os três últimos comandos exigem chave no ambiente e fazem chamadas pagas ao provedor; não integram CI automática. Não forneça a chave como argumento. `validate` executa testes, build reproduzível, gateway CLI, smoke Chromium, regressão DOM e auditorias. Limitações interativas são registradas pelo smoke, não tratadas como confirmação nativa.

Para rollback, remova a candidata e carregue o pacote anterior preservado em `release/recovery-0.2.1/`, verificando seu checksum. Reative somente permissões necessárias e reinsira a credencial da sessão. Nenhuma implantação produtiva ou merge automático é feito por este roteiro.
