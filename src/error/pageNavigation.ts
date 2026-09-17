import type { Request } from 'express';

/**
 * Quem pediu e uma PESSOA navegando, e nao um `fetch` de dentro da pagina.
 *
 * E o criterio de toda resposta que precisa ser entendida por gente: sessao
 * morta vira 302 para o login, e login recusado volta ao front com um codigo.
 * Para chamada de API, as duas continuam JSON. Um criterio so, para as duas
 * decisoes nunca discordarem sobre a mesma requisicao.
 *
 * `Sec-Fetch-Dest: document` e o sinal confiavel: e header proibido, que so o
 * navegador escreve. `fetch` de dentro de uma pagina manda `empty`. O `Accept`
 * e o plano B para cliente que nao manda `Sec-Fetch-*`.
 */
export function isPageNavigation(req: Request): boolean {
  const destino = req.headers['sec-fetch-dest'];

  if (typeof destino === 'string') return destino === 'document';

  return (req.headers.accept ?? '').includes('text/html');
}
