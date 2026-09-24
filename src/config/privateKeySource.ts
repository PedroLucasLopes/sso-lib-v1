import * as fs from 'node:fs';

export interface PrivateKeySource {
  pem?: string;
  base64?: string;
  file?: string;
}

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
    return source.pem.replace(/\\n/g, '\n').trim();
  }

  throw new Error(
    'nenhuma fonte de chave privada informada; defina file, base64 ou pem',
  );
}
