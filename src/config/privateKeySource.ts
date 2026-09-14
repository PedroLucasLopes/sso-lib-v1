import * as fs from 'node:fs';

export interface PrivateKeySource {
  /** PEM literal. So e pratico fora de container. */
  pem?: string;
  /** PEM em base64. E o formato que sobrevive a uma variavel de ambiente. */
  base64?: string;
  /** Caminho de arquivo. Use com secret montado (Cloud Run, Kubernetes). */
  file?: string;
}

/**
 * Resolve a chave privada da aplicacao a partir da fonte disponivel.
 *
 * PEM tem quebras de linha, e variavel de ambiente com quebra de linha e uma
 * fonte classica de dor: o docker compose, o Cloud Run e o shell tratam o
 * caractere de forma diferente. Por isso as tres fontes, em ordem de
 * preferencia decrescente de seguranca.
 *
 * `file` primeiro: secret montado nunca aparece em `docker inspect` nem no
 * painel do Cloud Run, ao contrario de variavel de ambiente.
 */
export function loadPrivateKeyPem(source: PrivateKeySource): string {
  if (source.file) {
    const pem = fs.readFileSync(source.file, 'utf8').trim();

    if (!pem) {
      throw new Error(`arquivo de chave privada vazio: ${source.file}`);
    }

    return pem;
  }

  if (source.base64) {
    const pem = Buffer.from(source.base64, 'base64').toString('utf8').trim();

    if (!pem.includes('BEGIN')) {
      throw new Error(
        'a chave privada em base64 nao decodifica para um PEM valido',
      );
    }

    return pem;
  }

  if (source.pem) {
    // Aceita `\n` escapado, que e como um PEM costuma sobreviver a um .env.
    return source.pem.replace(/\\n/g, '\n').trim();
  }

  throw new Error(
    'nenhuma fonte de chave privada informada; defina file, base64 ou pem',
  );
}
