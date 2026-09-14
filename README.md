# @pedrolucaslopes/sso-client

Conecta uma API NestJS ao SSO do ecossistema: OAuth 2.0 Authorization Code + PKCE, `private_key_jwt`,
sessão em cookie cifrado, renovação silenciosa, CSRF e RBAC por rota.

Padrão **token-mediating backend** (RFC 10017 §6.2). As decisões de desenho, os prazos que precisam
andar juntos e as invariantes estão em [`CLAUDE.md`](CLAUDE.md).

## API nova em quatro passos

### 1. Cadastrar no SSO

Pelo console do SSO: o projeto, a redirect URI `<APP_BASE_URL>/auth/callback`, as rotas que a API
expõe e os papéis. Gere a chave de cliente, associe os usuários e ative o projeto. A chave privada é
mostrada **uma única vez**: ela vira segredo da API, nunca arquivo versionado.

### 2. Instalar

O pacote é **privado** e mora no GitHub Packages, que exige token até para instalar.

`.npmrc` da aplicação, versionado:

```ini
@pedrolucaslopes:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${NODE_AUTH_TOKEN}
```

O token **não** entra no arquivo. Ele vem da variável de ambiente `NODE_AUTH_TOKEN`: um token
**clássico** do GitHub com `read:packages`, porque o GitHub Packages não aceita token fine-grained. No
build do Docker, passe como secret do BuildKit, nunca como `ARG` ou `ENV`, que ficam gravados na imagem.

```bash
npm i @pedrolucaslopes/sso-client @nestjs/config
```

### 3. Uma linha no `app.module.ts`

```ts
import { ConfigModule } from '@nestjs/config';
import { SsoClientModule } from '@pedrolucaslopes/sso-client';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    SsoClientModule.forRootFromEnv(),
  ],
})
export class AppModule {}
```

Nada no `main.ts`: o módulo registra o `cookie-parser` sozinho.

### 4. Preencher o `.env`

| Variável | Obrigatória | O que é |
|---|---|---|
| `SSO_ISSUER` | sim | identidade pública do SSO, sem barra final. Ex.: `https://exemplo.com/sso` |
| `APP_CLIENT_ID` | sim | client id do projeto no SSO |
| `APP_PRIVATE_KEY_FILE` · `APP_PRIVATE_KEY_BASE64` · `APP_PRIVATE_KEY` | uma delas | chave privada gerada pelo SSO. Arquivo de secret montado é a preferida |
| `APP_BASE_URL` | sim | base pública da API vista pelo navegador, com o prefixo global. Ex.: `https://exemplo.com/api` |
| `COOKIE_SECRET` | sim | 32 bytes em hex, próprio desta API: `openssl rand -hex 32` |
| `SSO_INTERNAL_URL` | não | endereço de rede do SSO, quando diferente do issuer. Ex.: `http://sso:8080/sso` |
| `APP_COOKIE_PREFIX` | não | prefixo dos cookies. Único entre aplicações que dividam host |
| `APP_POST_LOGIN_REDIRECT` | não | destino depois do login, quando não há `returnTo` |
| `APP_SESSION_MAX_AGE` | não | vida do cookie de sessão, em segundos. Acompanha o refresh token do SSO |
| `APP_ROUTE_PREFIX` | não | prefixo removido antes de casar com as permissões. Padrão: o caminho de `APP_BASE_URL` |
| `COOKIE_SECURE` | não | `false` só em desenvolvimento sobre HTTP |
| `COOKIE_SAMESITE` | não | `strict` (padrão), `lax` ou `none` |

Configuração incompleta não sobe: a API para no boot e a mensagem lista **tudo** o que falta, pelo nome,
sem mostrar valor nenhum.

## O que a API ganha

- As rotas `/auth/login`, `/auth/callback`, `/auth/token`, `/auth/logout` e `/auth/me`.
- Um guard global que **fecha por padrão**: rota nova só responde com sessão válida e com a permissão
  cadastrada no SSO. Esquecer o decorator nega, em vez de liberar.

| Decorator | Efeito |
|---|---|
| `@SsoPublic()` | ignora sessão e RBAC. É o nível do health check |
| `@SsoAuthenticated()` | exige sessão, dispensa a permissão por rota |
| _(nenhum)_ | exige sessão **e** permissão |
| `@CurrentUser()` | injeta a identidade no handler |
| `@CurrentToken()` | injeta o access token verificado, para repassar adiante |

## O que o front precisa fazer

Escrita autenticada por cookie leva o header `X-CSRF-Token`, com o valor que `GET /auth/me` devolve.
Sessão expirada numa chamada de API volta como 401 com o endereço de login pronto:

```js
if (res.status === 401) {
  const { error, login_url } = await res.json();
  if (error === 'login_required') location.assign(login_url);
}
```

## Configuração em código

`SsoClientModule.forRootFromEnv({ cookiePrefix: 'minha_api' })` fixa no código o que a aplicação
preferir, e o resto continua vindo do ambiente. Para montar as opções de outro jeito, `forRoot` e
`forRootAsync` continuam disponíveis, e `ssoClientOptionsFromEnv()` devolve o objeto sem registrar nada.

## Testes de integração

`@pedrolucaslopes/sso-client/testing` cria sessão e token contra um SSO de verdade, substituindo o login
federado que nenhuma automação consegue fazer. Exige credenciais de operador do SSO alvo, que a aplicação
recebe no **próprio** `.env.test`. Nunca importe esse ponto de entrada em código de produção.

## Publicar uma versão

```bash
npm version patch
git push --follow-tags
```

A tag `v*` dispara `.github/workflows/publish.yml`, que confere se a tag bate com o `package.json`,
compila e publica com o `GITHUB_TOKEN` da própria execução.
