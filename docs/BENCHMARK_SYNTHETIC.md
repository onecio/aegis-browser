# Benchmark sintético do navegador

**Coleta:** 29/09/2026. **Escopo:** microbenchmark dos módulos atuais de extração e análise local em fixtures sintéticas, executado no Chrome e no Edge disponíveis neste ambiente. Não mede Gmail/Outlook reais, renderização de caixa de entrada nem o impacto completo da extensão em uso contínuo.

## Ambiente

- Windows 11 Home Single Language, versão 10.0.26200, x64
- Intel Core i5-12450HX, 12 processadores lógicos
- Node.js 24.14.1
- Chrome 154.0.8037.58
- Microsoft Edge 154.0.4258.37

## Método

Os módulos `EmailProviderAdapter`, `analyzeEmail`, `extractPageSnapshot` e `analyzePageSnapshot` foram empacotados a partir do código-fonte com esbuild e importados em páginas sintéticas servidas por `127.0.0.1`. Cada operação teve 50 aquecimentos e 50 amostras cronometradas; cada amostra é a média de 10 execuções cronometradas com `performance.now()`. p50 e p95 usam a amostra de rank mais próximo.

- **Abertura + análise:** localizar e extrair a mensagem sintética do adaptador e executar `analyzeEmail()` uma vez.
- **Triagem de 20:** extrair 20 linhas clonadas de uma única fixture e executar `analyzeEmail()` em cada linha. Não representa 20 mensagens distintas nem renderização real.
- **Página:** executar `extractPageSnapshot()` e `analyzePageSnapshot()` sobre uma página sintética curta.
- **Task duration e heap:** diferença agregada antes/depois do bloco de benchmark, incluindo importação de módulos, construção de fixtures, aquecimento e amostras. Não são custo isolado por análise.

## Resultados

Latências em milissegundos, p50/p95:

| Navegador | Operação | Gmail | Outlook | Genérico |
|---|---|---:|---:|---:|
| Chrome 154.0.8037.58 | Abertura + análise | 0,08 / 0,12 | 0,05 / 0,16 | 0,03 / 0,05 |
| Chrome 154.0.8037.58 | Triagem sintética de 20 | 0,63 / 0,83 | 0,67 / 0,97 | 0,62 / 0,92 |
| Edge 154.0.4258.37 | Abertura + análise | 0,05 / 0,15 | 0,05 / 0,07 | 0,04 / 0,06 |
| Edge 154.0.4258.37 | Triagem sintética de 20 | 0,58 / 0,77 | 0,62 / 0,85 | 0,58 / 0,85 |

| Navegador | Análise de página p50/p95 | Task duration agregado | Delta de heap agregado |
|---|---:|---:|---:|
| Chrome 154.0.8037.58 | 0,04 / 0,07 ms | 1.271,937 ms | 6.414.932 bytes |
| Edge 154.0.4258.37 | 0,05 / 0,10 ms | 1.180,279 ms | 3.026.340 bytes |

## Limites da medição

Os números descrevem apenas estas fixtures e esta máquina; não são metas de aceitação nem prova de desempenho em produção. As operações de inbox repetem a mesma linha sintética, e a medição de página usa DOM mínimo. Permanecem sem medição: inicialização e renderização em Gmail/Outlook reais, abertura de mensagem real, uso normal do navegador com a extensão ativa, custo incremental de CPU/memória por sessão e comparação contra navegador sem extensão. Precisão, recall, FPR/FNR, calibração, rede e custo por mil mensagens também não foram medidos; o seed atual contém apenas 18 cenários sintéticos e não permite calibrar limiares.
