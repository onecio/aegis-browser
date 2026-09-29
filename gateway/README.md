# AEGIS Gateway

Serviço corporativo intermediário entre a extensão AEGIS e o System One/JEV. A chave do provedor permanece exclusivamente no servidor. Clientes autenticam-se com token OIDC de curta duração.

## Execução local

1. Copie `.env.example` para um arquivo de configuração fora do repositório.
2. Defina `TYPESAFE_API_KEY` no ambiente do processo. Não grave a chave na imagem nem no Git.
3. Configure emissor, JWKS, audiência, escopo, tenants e origens exatas da extensão.
4. Execute `npm run gateway` atrás de um proxy reverso HTTPS.

O endpoint de análise é `POST /v1/systemone`; a verificação operacional é `GET /health`.

## Contêiner

Use a raiz do repositório como contexto:

```text
docker build -f gateway/Dockerfile -t aegis-gateway:local .
docker run --rm --env-file C:\segredos\aegis-gateway.env -e AEGIS_GATEWAY_HOST=0.0.0.0 -p 127.0.0.1:8787:8787 aegis-gateway:local
```

O endereço HTTP local serve apenas para a verificação do contêiner. A extensão aceita gateway HTTPS. Para acesso pela extensão, termine TLS em um proxy confiável, limite a rede de origem e mantenha `AEGIS_GATEWAY_HOST=0.0.0.0` dentro do contêiner.

## Modos de teste da extensão

- **JEV no gateway:** selecione Gateway, informe a URL HTTPS e um token OIDC válido; a chave TypeSafe fica somente no ambiente do gateway.
- **JEV direto na extensão:** selecione BYOK e informe a chave na tela de configurações. A credencial fica em `chrome.storage.session` e não persiste após o encerramento da sessão do navegador.
- **JEV desativado:** desligue a inteligência assistida. As regras locais, a proteção de páginas, a triagem de e-mail, a detecção de ClickFix e a marcação de busca continuam operando sem chamadas externas.

A preferência de proteção permanece salva até o usuário desativá-la. Credenciais permanecem temporárias por segurança e precisam ser reapresentadas quando a sessão expirar.
