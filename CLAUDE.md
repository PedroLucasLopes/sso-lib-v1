# 🔌 @pedrolucaslopes/sso-client

Camada de autenticação reutilizável. Conecta uma aplicação NestJS ao ecossistema do SSO.

O padrão é o **token-mediating backend** da RFC 10017 §6.2, não o BFF da §6.1. A distinção importa:

- A aplicação é um **backend registrado no SSO**, cliente confidencial, e conduz o Authorization
  Code + PKCE (§6.2.3.1 exige que seja confidencial).
- O **refresh token fica no servidor**, ligado à sessão (§6.2.2.2). Não chega ao cliente.
- O **access token é entregue** a quem tem a sessão, por `GET /auth/token` (§6.2.2.1, o endpoint que
  a RFC chama de "check session"). Daí em diante vale `Authorization: Bearer`.

Num BFF o token nunca sairia do servidor. Aqui ele sai, de propósito, porque quem consome a API é a
própria aplicação e, mais adiante, o front dela.

Existe para que uma aplicação nova não repita a configuração inteira. O custo de entrar no
ecossistema é uma linha e as variáveis de ambiente da tabela no fim deste arquivo:

```ts
@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    SsoClientModule.forRootFromEnv(),
  ],
})
```

**`forRootFromEnv` lê um contrato de nomes, não uma configuração solta.** `SSO_ISSUER`,
`APP_CLIENT_ID`, a chave privada, `APP_BASE_URL` e `COOKIE_SECRET` têm o mesmo nome em toda aplicação,
então o `.env` de uma serve de modelo para a próxima. Configuração incompleta derruba o boot com a
lista inteira do que falta, pelo nome e sem mostrar valor: descobrir uma variável por vez é o que
transforma configuração em tarde perdida. `forRoot` e `forRootAsync` continuam para quem monta as
opções de outro jeito, e `ssoClientOptionsFromEnv()` devolve o objeto sem registrar nada.

**O `cookie-parser` é registrado pelo módulo.** Sem ele `req.cookies` chega vazio, a sessão nunca é
lida e a pessoa entra num laço de login sem erro nenhum, nem na tela nem no log. Era um passo manual no
bootstrap, e o mais fácil de esquecer numa API nova. Quem também registra no `main.ts` não é afetado: o
middleware pula a requisição cujos cookies já foram lidos. O krloc roda o `test:sso` inteiro sem
registrar o dele.

---

## 📦 Distribuição

O pacote é **`@pedrolucaslopes/sso-client`**, privado, no GitHub Packages, com repositório próprio em
`PedroLucasLopes/sso-lib-v1`. O nome do repositório não precisa bater com o do pacote; o escopo do npm
tem de ser o dono no GitHub, em minúsculas.

- **Publicar:** `npm version patch` e `git push --follow-tags`. A tag `v*` dispara
  `.github/workflows/publish.yml`, que confere a tag contra a versão e publica com o `GITHUB_TOKEN`
  da própria execução. Nenhum token pessoal fica guardado em secret.
- **Instalar:** `.npmrc` com `@pedrolucaslopes:registry=https://npm.pkg.github.com` e
  `//npm.pkg.github.com/:_authToken=${NODE_AUTH_TOKEN}`. O token, com `read:packages`, vem do
  ambiente. No Docker entra como secret do BuildKit, nunca como `ARG` ou `ENV`, que ficam na imagem.

Publicado desde a `0.1.0`. Quem consome instala por versão, e o krloc faz exatamente isso: não há
workspace npm nem link de pasta. Para testar uma mudança antes de publicar, `npm pack` aqui e
`npm install --no-save <arquivo .tgz>` na aplicação; a próxima instalação normal volta à versão
publicada.

**Não introduza dependência de nada fora de `sso-client/src`.** É o que mantém o pacote independente.

---

## 🎁 O que o módulo entrega

Ao ser importado, ele registra quatro rotas e um guard global:

| Rota | Nível | O que faz |
|---|---|---|
| `GET /auth/login` | `@SsoLogin()` | gera PKCE, grava a transação em cookie, redireciona ao SSO |
| `GET /auth/callback` | `@SsoLogin()` | valida `state` e `iss`, troca o code, cria a sessão, devolve o bounce |
| `GET /auth/token` | `@SsoAuthenticated()` | **entrega o access token**, renovando se preciso |
| `POST /auth/logout` | `@SsoAuthenticated()` | revoga no SSO (RFC 7009) e limpa o cookie |
| `GET /auth/me` | `@SsoAuthenticated()` | identidade, permissões e **token anti-CSRF** do usuário corrente |

O guard aceita **duas** formas de credencial, nesta precedência:

1. `Authorization: Bearer <token>` (RFC 6750 §2.1). Explícito, e é como a aplicação chama a API
   depois de pegar o token. Não carrega risco de CSRF.
2. Cookie de sessão. Implícito, usado pela navegação direta, e a única forma que permite renovação
   automática, porque o refresh token só existe do lado do servidor.

**Quando a identificação vem pelo cookie, o guard preenche o `Authorization` no request.** Isso
acontece depois da verificação, nunca antes: token que não passou não entra no request. A partir
daí existe um caminho só, e nem controller, nem interceptor, nem chamada de saída precisa saber
como o usuário se identificou.

Bearer inválido devolve 401 mas **não** descarta a sessão: token ruim é problema de quem enviou.

### ⏳ Enquanto o refresh token viver, ninguém vê tela de login

O fluxo, do jeito que ele de fato acontece:

```
access token válido            -> segue
access token perto de vencer   -> renova em silêncio, na própria requisição
access token não verifica      -> tenta renovar mesmo assim, e só então desiste
refresh token morto            -> aí sim, login
```

A terceira linha é a que menos se espera e a que mais salva. Um access token pode deixar de
verificar sem a sessão estar ruim: rotação de chave de assinatura no SSO, relógio fora de hora. Sem
a tentativa de renovação, uma rotação de chave deslogaria todo mundo ao mesmo tempo.

**Quatro prazos precisam estar alinhados, e o menor deles é quem manda:**

| Prazo | Onde | Hoje |
|---|---|---|
| `ACCESS_TOKEN_TTL` | SSO | 15 minutos |
| `REFRESH_TOKEN_TTL` | SSO | 90 dias |
| `AUTH_SESSION_TTL` | SSO | 90 dias |
| `sessionMaxAgeSeconds` | esta biblioteca | 90 dias |

A `AuthSession` é a mais fácil de esquecer. A RFC 10017 §6.3.2.3 amarra a vida do refresh token à
da sessão, e o SSO implementa isso: sessão curta mata refresh token longo, por mais folgado que ele
seja. O cookie é a outra: se ele expirar antes, o navegador o descarta e a pessoa vai ao login sem
nenhum sinal do lado do servidor.

**Por que o access token não acompanha.** Ele é a única credencial do conjunto que não pode ser
cancelada: é assinada e conferida sem consulta, que é o que dispensa o RP de falar com o SSO a cada
requisição. Tudo que é longo aqui mora no servidor e é revogável. Fazer o access token durar dias
transformaria cada logout numa promessa que o sistema não cumpre, e cada revogação de papel numa
espera de dias.

**Logout.** `POST /auth/logout` revoga no SSO (RFC 7009) e limpa o cookie. A revogação derruba a
família de refresh tokens, então a sessão não renova mais, e o navegador fica sem cookie e sem
token. O access token que porventura já tenha sido copiado para fora continua verificando até
expirar, e é por isso que ele dura minutos. Revogar pelo access token também funciona: o SSO usa a
claim `sid` para achar o mesmo grant.

### 🔁 Sessão morta manda ao login e traz de volta

Um 401 seco é a resposta certa para um cliente de API e a resposta errada para uma pessoa. Ela
estava numa tela, a sessão expirou enquanto ela lia, e o que ela precisa é voltar àquela tela depois
de entrar de novo. O guard levanta `SsoLoginRequiredException` e o
`SsoLoginRequiredFilter`, registrado como `APP_FILTER`, decide a forma da resposta:

| Quem pediu | Sinal | Resposta |
|---|---|---|
| Navegação de página | `Sec-Fetch-Dest: document`, ou `Accept: text/html` | `302` para `/auth/login?returnTo=…` |
| Chamada de API | qualquer outro | `401` com `error: "login_required"` e `login_url` |

**Por que não 302 para todo mundo.** O `fetch` segue redirect sozinho e em silêncio. O front pediria
JSON e receberia o HTML do SSO, sem nenhum sinal do que houve. O 401 com corpo nomeado deixa o front
guardar o estado dele e navegar por conta própria.

**De onde sai o `returnTo`.** Depende do caso, e os dois importam:

- **Navegação:** `req.originalUrl`. A pessoa pediu aquela URL, é para lá que ela volta.
- **API:** o `Referer`. `req.originalUrl` seria `/api/accessory`, uma rota de backend, e não a tela
  que a pessoa via. O `Referer` de um `fetch` same-origin carrega a página que disparou a chamada,
  que é exatamente `/accessories`. É o único lugar onde o backend fica sabendo disso.

`Referer` é entrada do navegador, então passa por `safeReturnTo` como qualquer destino. `Referer` de
outro site cai no padrão, senão o redirect aberto voltaria por um caminho lateral.

**Por que 302 e não 307.** A volta do login é sempre `GET`, mesmo que o pedido original fosse
`POST`. Repetir um `POST` depois do login seria surpresa, e das ruins.

**O que o front precisa fazer:**

```js
const res = await fetch('/api/accessory');

if (res.status === 401) {
  const { error, login_url } = await res.json();
  if (error === 'login_required') location.assign(login_url);
}
```

O `login_url` já vem com o `returnTo` embutido. Se o front preferir mandar outro destino, é só trocar
o parâmetro: `safeReturnTo` valida do mesmo jeito.

**O guard não chama `res.redirect()`.** Ele lança. Um guard que responde e devolve `false` faz o Nest
tentar responder de novo, e o resultado é "Cannot set headers after they are sent". Já aconteceu
neste projeto, e é por isso que a decisão mora num filtro.

### 🛡️ CSRF: o preço de autenticar por cookie

A RFC 10017 §6.2.3.2 exige que o token-mediating backend se defenda de CSRF, e a razão é mecânica:
o navegador anexa o cookie de sessão mesmo quando quem disparou a requisição foi **outro site**. O
`Authorization: Bearer` não tem esse problema, porque o navegador nunca o anexa sozinho.

Por isso a defesa vale **só** quando a credencial veio do cookie, e **só** em método que muda
estado. `GET`, `HEAD` e `OPTIONS` passam direto: o atacante até dispara a requisição, mas a política
de mesma origem impede que ele leia a resposta.

São duas barreiras:

1. **Token de dupla submissão.** A cópia autoritativa vive **dentro** do cookie de sessão, que é
   cifrado. A cópia legível chega no cookie `<prefixo>_csrf`, que **não** é `HttpOnly` de propósito, e o
   front a devolve no header `X-CSRF-Token`. Quem consegue apenas **gravar** cookie no domínio, por
   subdomínio tomado ou resposta injetada, não produz um par que bata, porque não sabe cifrar o
   lado de dentro. A comparação é em tempo constante.
2. **`Origin`.** Recusado quando **presente** e de outro site. Não é exigido, para não quebrar
   cliente que não o envia. É barreira extra, não a principal.

A checagem acontece **antes** da renovação silenciosa do access token, de propósito: requisição
forjada não pode consumir uma rotação de refresh token.

O token sobrevive à renovação. Trocá-lo a cada refresh silencioso invalidaria a cópia que o front
já tem em mão, e a escrita seguinte falharia sem motivo aparente.

**O que o front precisa fazer**, em uma linha:

```js
fetch('/api/equipment', { method: 'POST', headers: { 'X-CSRF-Token': csrf }, body });
```

O valor sai de `GET /auth/me`, que também devolve `csrfCookieName`, ou do próprio cookie. Quem já pegou o token em `GET /auth/token` e
manda `Authorization: Bearer` não precisa de nada disso.

### 🍪 O nome do cookie leva prefixo por aplicação

Os cookies são `<prefixo>_session`, `<prefixo>_tx` e `<prefixo>_csrf`. O prefixo vem de
`cookiePrefix`, ou de oito dígitos derivados do `clientId` quando não informado.

**Não é enfeite.** Cookie é escopado por **host**, e a RFC 6265 §8.5 é explícita: não há isolamento
por porta. Duas aplicações em `localhost:3000` e `localhost:4000` dividem o mesmo pote. Com nome
fixo, a segunda a fazer login sobrescreveria a sessão da primeira, e o cookie anti-CSRF de uma
seria legível pelo JavaScript da outra. Em produção, com domínios distintos, o problema não
aparece; em desenvolvimento ele aparece no dia em que existir a segunda aplicação.

O front lê `csrfCookieName` de `GET /auth/me` em vez de fixar a string.

> Em desenvolvimento, hosts distintos isolam de verdade: `krloc.localhost` e `sso.localhost`
> resolvem para 127.0.0.1 nos navegadores atuais e têm potes de cookie separados. O prefixo
> continua valendo como segunda camada.

### 🔒 `SameSite=Strict` e o salto do callback

O padrão é `strict`, como a RFC 10017 §6.1.3.2 pede. Conseguir isso custou uma peça a mais, e vale
entender por quê antes de mexer no callback.

`SameSite` compara **site**, não origem: porta e subdomínio não contam. `localhost:3000` e
`localhost:8080` são o mesmo site, e `app.exemplo.com` e `sso.exemplo.com` também. Só um domínio
registrável diferente quebraria.

O problema não é esse. É o **retorno do provedor federado**. A cadeia é:

```
accounts.google.com  ──►  SSO  ──►  app /auth/callback  ──►  app /home
```

O navegador avalia a cadeia inteira, e como ela começa em outro site, um `302` no último salto
chegaria a `/home` **sem o cookie**: `Strict` não acompanha navegação iniciada de fora. A página
devolveria 401, mandaria o usuário para `/auth/login`, o SSO ainda teria sessão viva, emitiria o
code na hora, e o ciclo recomeçaria. É um **laço de login**, não um erro visível, e foi exatamente
o que derrubou o OIDC do Quarkus com `sameSite=strict`.

A saída: o callback **não** devolve `302`. Ele devolve um documento HTML da própria origem, com
`<meta http-equiv="refresh">` apontando para o destino. A navegação passa a ser iniciada por **este**
documento, que é same-site, e aí o cookie `Strict` vai junto. Custa um carregamento a mais e nenhum
JavaScript: nada de script inline, para não colidir com a CSP de quem usa a biblioteca.

O cookie de **transação** continua `lax` sempre, com override explícito. Ele precisa sobreviver ao
salto cross-site do retorno, senão o callback chega sem `code_verifier` e o login morre antes de
começar.

**Não troque o `bounceTo` por um `res.redirect()`.** Parece simplificação e é a regressão do laço.

### 🚪 `returnTo` não é redirect aberto

`returnTo` chega pela query string, então é entrada do atacante. `safeReturnTo` aceita caminho
relativo com uma barra só, ou URL absoluta da própria origem; qualquer outra coisa cai no destino
padrão. Sem isso, `?returnTo=https://phishing.example` transformaria a rota de login numa máquina
de encaminhar vítimas partindo de um domínio confiável. Há teste de regressão cobrindo
`//host`, `/\host` e o truque do `\@`.


**O guard é global e fecha por padrão.** Rota nova nasce protegida; esquecer o decorator nega o
acesso em vez de liberá-lo.

**Rota negada responde 404, não 403.** O corpo é o mesmo do roteador do Nest para um caminho que não
existe: `Cannot GET /api/accessory`. Rota que existe no código mas não está no catálogo do SSO, ou
não está no papel de quem pediu, fica indistinguível de rota que não existe (RFC 9110 §15.5.4). Sem
sessão continua 401, porque a pessoa precisa saber que tem de entrar.

| Decorator | Efeito |
|---|---|
| `@SsoPublic()` | ignora sessão e RBAC. É o nível do health check |
| `@SsoLogin()` | rota do fluxo de login, onde ainda não há sessão |
| `@SsoAuthenticated()` | exige sessão válida, dispensa a checagem de permissão por rota |
| _(nenhum)_ | exige sessão **e** permissão do papel para a rota. Sem ela, 404 |
| `@CurrentUser()` | injeta a identidade resolvida no handler |
| `@CurrentToken()` | injeta o access token já verificado, para repassar adiante |

---

## 🧪 `@pedrolucaslopes/sso-client/testing`

Ponto de entrada separado, com o que uma aplicação precisa para testar a si mesma contra um SSO de
verdade: criar sessão, emitir token administrativo, limpar o que a rodada criou.

Mora aqui por causa da **independência**. Cada aplicação do ecossistema tem repositório e
infraestrutura próprios; se o teste de uma delas importasse código de dentro do SSO, a
independência seria de fachada. Este pacote já é o contrato entre o SSO e quem se conecta, então é
ele que viaja junto.

```js
const { ensureProjectUser, mintAdminToken, purgeTestUsers } =
  require('@pedrolucaslopes/sso-client/testing');
```

⚠️ **Nada disso é para produção.** Tudo pressupõe credenciais de operador do SSO alvo: a conexão do
banco e a `COOKIE_SECRET`. A aplicação as recebe no próprio `.env.test`, nunca lendo arquivo de
outro projeto. O que elas substituem é o login federado, que nenhuma automação consegue fazer; o
resto do caminho é real.

Não depende de `pg`: quem chama passa o cliente já conectado, pela interface `SqlClient`.

---
## 📁 Estrutura

```bash
src/
├─ ssoClient.module.ts      # forRoot / forRootAsync
├─ ssoClient.constant.ts    # nomes de cookie, chaves de metadata, token de injeção
├─ config/                  # opções + resolução da chave privada
├─ controller/              # as quatro rotas acima
├─ cookie/                  # AEAD (AES-256-GCM) + cookie cifrado e cookie legível
├─ decorator/               # níveis de acesso + @CurrentUser
├─ dto/                     # tipos de sessão, claims, metadados do AS
├─ error/                   # SsoLoginRequiredException + o filtro que a traduz
├─ testing/                 # ponto de entrada @pedrolucaslopes/sso-client/testing
├─ guard/                   # SsoRbacGuard
└─ service/                 # discovery · jwks · client assertion · oauth · sessão
```

---

## 🧠 Decisões que não são óbvias

**Identidade pública ≠ endereço de rede.** `issuer` é a claim `iss` e a URL que o **navegador**
visita. `internalBaseUrl` é por onde **este processo** fala com o SSO. Em container, `localhost`
aponta para o próprio processo, não para o SSO. O discovery e o token endpoint saem pelo endereço
interno; o authorize continua público. A validação não afrouxa: o `issuer` devolvido pelo discovery
ainda tem de bater com o configurado, como manda a RFC 8414 §3.3.

Consequência: o `aud` da asserção de cliente usa `token_endpoint_public`, não o interno. O SSO
valida a audiência contra a própria URL pública.

**O caminho da requisição nunca vira padrão de autorização.** Quem é compilado em regex é a
**permissão**, que é cadastrada por administrador. A implementação anterior fazia o inverso,
montando `new RegExp(req.path)`, o que transformava metacaractere no caminho em bypass: um pedido a
`/api/.*` casava com qualquer permissão. Há teste de regressão para isso em `krloc/test/sso-e2e.js`.

**O cookie de transação é sempre `lax`, mesmo quando a sessão é `strict`.** O retorno do SSO pode
ser uma navegação cross-site, e `Strict` não acompanha esse salto: o callback chegaria sem transação.

**O logout tem que revogar no servidor.** Limpar o cookie só apaga a cópia do navegador. Sem chamar
o revoke da RFC 7009, qualquer outra cópia continuaria renovando indefinidamente. O access token já
emitido segue válido até expirar, o que é inerente a token assinado e sem consulta: é por isso que
ele dura minutos, e é o limite explícito que a RFC 10017 §6.2.4 reconhece neste padrão.

**A verificação de JWT tem allowlist de algoritmo.** Aceitar o `alg` do próprio token é a brecha
clássica de confusão de algoritmo: `none` passa direto e `HS256` permitiria assinar com a chave
pública, que é conhecida. Só `RS256` é aceito.

**O JWKS tem cooldown de rebusca.** `kid` desconhecido normalmente significa rotação de chave, mas
sem cooldown um token com `kid` aleatório viraria vetor de carga contra o SSO.

**O token traz `roles`, não a lista de rotas.** RFC 9068 §2.2.3.1. O `SsoPermissionsService`
resolve papel em permissões via `POST /oauth/permissions` e guarda o conjunto em memória, pela chave
papel mais hash `perm` do token. Uma busca por papel, não uma por requisição.

O banco do SSO é a fonte de verdade, e o que muda no console chega à aplicação por dois caminhos:

| Mudança no SSO | Vale na aplicação | Como |
|---|---|---|
| permissão concedida, ou rota nova no papel | na requisição seguinte | antes de negar, o guard pergunta de novo ao SSO, no máximo uma vez a cada 5 segundos por papel |
| permissão revogada | em até 60 segundos | cada conjunto guardado vale 60 segundos, e a requisição seguinte busca de novo |

Só o hash não bastava. Ele muda dentro do token apenas quando o token é renovado, e isso leva até
15 minutos: uma revogação feita no console continuava valendo esse tempo todo. **Com o SSO fora do
ar**, o último conjunto conhecido segue valendo até ele voltar. A janela é curta por construção: sem
o SSO nenhum token se renova, e o access token dura 15 minutos.

**Papel que o SSO não conhece mais**, apagado ou renomeado, não é SSO fora do ar: o
`POST /oauth/permissions` responde 404 e o conjunto vira vazio. Nada fica liberado até o token renovar
com o nome novo, em até 15 minutos.

Isso não é otimização, é correção. A versão anterior embutia as permissões no token, que crescia
com o número de rotas. Com 38 rotas o cookie de sessão passou de 4266 bytes e **o navegador o
descartava em silêncio**, sem erro nem log. O teste automatizado passava porque `fetch` não aplica
o limite de 4096 bytes que o navegador aplica. Há teste de regressão de tamanho de cookie em
`krloc/test/sso-e2e.js`; **não o remova.**

---

## ⚙️ Variáveis que a aplicação precisa

Lidas por `forRootFromEnv`. **O nome é contrato:** renomear uma delas quebra toda aplicação instalada.

| Chave | Uso |
|---|---|
| `SSO_ISSUER` | identidade pública do SSO, sem barra final |
| `SSO_INTERNAL_URL` | endereço de rede do SSO, quando diferente. Ex.: `http://host.docker.internal:8080/sso`, de dentro de um container |
| `APP_CLIENT_ID` | `Project.clientId` cadastrado no SSO |
| `APP_PRIVATE_KEY_FILE` · `APP_PRIVATE_KEY_BASE64` · `APP_PRIVATE_KEY` | chave privada da aplicação, nesta ordem de preferência. Ver abaixo |
| `APP_BASE_URL` | base pública desta aplicação, com o prefixo global |
| `COOKIE_SECRET` | 32 bytes hex que cifram os cookies |
| `COOKIE_SECURE` · `COOKIE_SAMESITE` | atributos dos cookies |
| `APP_COOKIE_PREFIX` | prefixo dos nomes de cookie (`cookiePrefix`). **Único por aplicação que divida host** |
| `APP_SESSION_MAX_AGE` | vida do cookie de sessão (`sessionMaxAgeSeconds`). Acompanha o refresh token do SSO |
| `APP_POST_LOGIN_REDIRECT` · `APP_ROUTE_PREFIX` | destino depois do login e prefixo removido antes do RBAC |

`loadPrivateKeyPem` aceita três fontes, nesta ordem de preferência: `file` (secret montado, que não
aparece em `docker inspect` nem no painel do Cloud Run), `base64` e `pem` literal. PEM tem quebra de
linha, que sobrevive mal a uma variável de ambiente.

> ⚠️ A chave privada é gerada **pelo SSO**, em `POST /sso/clientkey/generate`, e devolvida uma única
> vez. O SSO guarda só a metade pública. A entrega ao dono da aplicação é um ato humano, por canal
> seguro. Nenhuma ferramenta deste repositório grava a chave em disco ou a imprime em terminal.

---

## ✅ Invariantes ao alterar

- O **refresh token** nunca sai do servidor (RFC 10017 §6.2.2.2). O access token, sim, e só por
  `GET /auth/token`.
- Os quatro prazos andam juntos: `ACCESS_TOKEN_TTL` curto, e `REFRESH_TOKEN_TTL`,
  `AUTH_SESSION_TTL` e `sessionMaxAgeSeconds` iguais entre si. Mexer num só cria uma expiração
  que ninguém consegue explicar.
- Nada que cresça com o tamanho do projeto entra no token. Ele tem orçamento: cabe num cookie de
  4 KB e num header de 8 KB, com folga.
- O caminho da requisição é sempre texto testado, nunca padrão.
- Algoritmo de assinatura é allowlist fechada, nunca lido do token.
- Rota sem decorator nega. Não inverta esse padrão.
- Rota negada devolve o 404 do roteador, `Cannot <MÉTODO> <URL>`, sem `WWW-Authenticate`. Um 403 ali
  revelaria que a rota existe.
- Permissão concedida vale sem novo login, e a revogada, em até 60 segundos. Cache sem prazo volta a
  deixar uma revogação valendo até o token renovar.
- Escrita autenticada por cookie exige o header `X-CSRF-Token`. Não afrouxe isso sem trocar por
  outra defesa: a RFC 10017 §6.2.3.2 exige alguma.
- O callback devolve documento, não `302`. Trocar por `res.redirect()` recria o laço de login com
  `SameSite=Strict`.
- O cookie de transação é sempre `lax`, mesmo quando a sessão é `strict`.
- Nome de cookie nunca é fixo entre aplicações. Cookie não isola por porta (RFC 6265 §8.5).
- `returnTo` passa por `safeReturnTo` antes de virar destino. Sempre.
- Sessão morta nunca devolve 401 seco para navegação de página. Quem decide a forma da resposta é o
  filtro, não o guard.
- O que está em `testing/` exige credencial de operador do SSO e **nunca** sai do ponto de entrada
  separado. Não reexporte pelo `index.ts`.
- Rode `npm run test:sso` no krloc depois de mexer aqui: é o teste que exercita a biblioteca inteira.
- Nome de variável lida por `forRootFromEnv` é contrato. Renomear, ou tornar obrigatória uma opcional,
  quebra quem já instalou e pede versão `major`.
- Configuração incompleta cita nomes, nunca valores: metade das variáveis é segredo.
- O `cookie-parser` fica registrado pelo módulo. Tirar recria o laço de login silencioso numa API nova.
