/**
 * Micro-serviço Proxy mTLS SEFAZ em Node.js (OpenSSL nativo).
 *
 * Por que este proxy é necessário:
 * O webservice NFeDistribuiçãoDFe da SEFAZ (tanto Homologação quanto Produção)
 * exige autenticação mTLS (Mutual TLS com certificado A1 e-CNPJ) e provoca
 * RENEGOCIAÇÃO de sessão TLS iniciada pelo servidor durante o handshake/conexão.
 *
 * Runtimes baseados em rustls (como o Deno Deploy) NÃO suportam renegociação TLS
 * iniciada pelo servidor (issue denoland/deno#32245). O Go padrão também recusa por default.
 *
 * O Node.js com o módulo nativo `node:https` e OpenSSL oferece suporte total:
 *  - Certificado A1 PKCS#12 (.pfx / .p12) com passphrase
 *  - Renegociação TLS tolerada via SSL_OP_LEGACY_SERVER_CONNECT
 *  - HTTP/1.1 forçado (a SEFAZ rejeita HTTP/2)
 *  - TLSv1.2 como versão mínima
 *
 * Segurança:
 *  - Nunca loga nem ecoa a senha ou o conteúdo binário do certificado na resposta/logs.
 *  - Validação opcional de cabeçalho `x-proxy-secret` via variável PROXY_SECRET ou SEFAZ_PROXY_SECRET.
 *  - Pode ser executado em qualquer ambiente Node.js gratuito (Render.com free tier, Fly.io, Hugging Face Spaces, VPS).
 */

const https = require('node:https')
const http = require('node:http')
const crypto = require('node:crypto')
const url = require('node:url')

const PORT = Number(process.env.PORT) || 8080
const PROXY_SECRET = process.env.PROXY_SECRET || process.env.SEFAZ_PROXY_SECRET || ''

/**
 * Cria a instância da aplicação HTTP/proxy.
 */
function createProxyServer() {
  return http.createServer(async (req, res) => {
    // Cabeçalhos CORS padrão
    res.setHeader('Access-Control-Allow-Origin', '*')
    res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
    res.setHeader(
      'Access-Control-Allow-Headers',
      'Content-Type, X-Proxy-Secret, x-proxy-secret, Authorization',
    )

    if (req.method === 'OPTIONS') {
      res.writeHead(204)
      return res.end()
    }

    // Healthcheck endpoint
    if (req.method === 'GET' && (req.url === '/' || req.url === '/health')) {
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' })
      return res.end(
        JSON.stringify({
          status: 'ok',
          service: 'sefaz-mtls-proxy-node',
          runtime: 'Node.js ' + process.version,
          features: ['mTLS', 'PKCS12/PFX', 'TLSv1.2', 'HTTP/1.1', 'OpenSSL-Legacy-Renegotiation'],
          authRequired: Boolean(PROXY_SECRET),
          timestamp: new Date().toISOString(),
        }),
      )
    }

    if (req.method !== 'POST' || !req.url.startsWith('/mtls-forward')) {
      res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8' })
      return res.end(
        JSON.stringify({
          success: false,
          error: 'Endpoint não encontrado. Utilize POST /mtls-forward ou GET /health.',
        }),
      )
    }

    // Validação de token de segurança compartilhado (quando configurado no servidor)
    if (PROXY_SECRET) {
      const providedSecret = req.headers['x-proxy-secret'] || req.headers['X-Proxy-Secret'] || ''
      if (providedSecret !== PROXY_SECRET) {
        res.writeHead(401, { 'Content-Type': 'application/json; charset=utf-8' })
        return res.end(
          JSON.stringify({
            success: false,
            error: 'Não autorizado. Token de segurança do proxy inválido ou ausente.',
          }),
        )
      }
    }

    // Leitura do corpo JSON com limite de segurança de 15MB
    let bodyBuffer = ''
    let isPayloadTooLarge = false

    req.on('data', (chunk) => {
      bodyBuffer += chunk
      if (bodyBuffer.length > 15 * 1024 * 1024) {
        isPayloadTooLarge = true
        res.writeHead(413, { 'Content-Type': 'application/json; charset=utf-8' })
        res.end(
          JSON.stringify({
            success: false,
            error: 'Payload excede o limite máximo suportado (15MB).',
          }),
        )
        req.destroy()
      }
    })

    req.on('end', async () => {
      if (isPayloadTooLarge) return

      let payload
      try {
        payload = JSON.parse(bodyBuffer)
      } catch (_) {
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' })
        return res.end(
          JSON.stringify({
            success: false,
            error: 'Corpo da requisição deve ser um JSON válido.',
          }),
        )
      }

      const {
        url: targetUrl,
        soapAction,
        soapBody,
        pfxBase64,
        passphrase = '',
        timeout = 60000,
      } = payload || {}

      if (!targetUrl || typeof targetUrl !== 'string') {
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' })
        return res.end(
          JSON.stringify({
            success: false,
            error: 'Parâmetro obrigatório "url" (endpoint oficial SEFAZ) ausente ou inválido.',
          }),
        )
      }

      if (!soapBody || typeof soapBody !== 'string') {
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' })
        return res.end(
          JSON.stringify({
            success: false,
            error: 'Parâmetro obrigatório "soapBody" (envelope XML) ausente ou inválido.',
          }),
        )
      }

      if (!pfxBase64 || typeof pfxBase64 !== 'string') {
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' })
        return res.end(
          JSON.stringify({
            success: false,
            error:
              'Parâmetro obrigatório "pfxBase64" ausente ou inválido para autenticação mTLS com a SEFAZ.',
          }),
        )
      }

      // Decodificação do certificado PFX em Base64
      let pfxBuffer
      try {
        const cleanBase64 = pfxBase64.replace(/\s+/g, '')
        pfxBuffer = Buffer.from(cleanBase64, 'base64')
        if (pfxBuffer.length < 100) {
          throw new Error('Tamanho de bytes insuficiente para um arquivo PKCS#12 (.pfx).')
        }
      } catch (b64Err) {
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' })
        return res.end(
          JSON.stringify({
            success: false,
            error:
              'Falha ao decodificar certificado A1 em Base64: arquivo corrompido ou formato inválido.',
          }),
        )
      }

      // Validação do endpoint de destino (protocolo HTTPS)
      let parsedUrl
      try {
        parsedUrl = new url.URL(targetUrl)
        if (parsedUrl.protocol !== 'https:') {
          throw new Error(
            'Apenas endpoints seguros (HTTPS) são aceitos para comunicação com a SEFAZ.',
          )
        }
      } catch (urlErr) {
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' })
        return res.end(
          JSON.stringify({
            success: false,
            error: 'URL de destino inválida: ' + (urlErr.message || String(urlErr)),
          }),
        )
      }

      // Configuração de segurança TLS OpenSSL:
      // - SSL_OP_LEGACY_SERVER_CONNECT: permite a renegociação iniciada pela SEFAZ
      // - TLSv1.2 como base exigida pela SEFAZ
      let secureOptions = 0
      if (crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT) {
        secureOptions |= crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT
      }

      let agent
      try {
        agent = new https.Agent({
          pfx: pfxBuffer,
          passphrase: String(passphrase || ''),
          rejectUnauthorized: false, // Cadeia ICP-Brasil intermediária varia por UF/homologação
          secureOptions: secureOptions,
          minVersion: 'TLSv1.2',
          maxVersion: 'TLSv1.3',
          keepAlive: false, // Não reutiliza conexões em renegociações esporádicas da SEFAZ
        })
      } catch (agentErr) {
        // Diagnóstico sem jamais expor passphrase ou certificado
        const rawMsg = agentErr ? agentErr.message || String(agentErr) : ''
        const isMacOrPassword =
          rawMsg.toLowerCase().includes('mac') ||
          rawMsg.toLowerCase().includes('pkcs12') ||
          rawMsg.toLowerCase().includes('password') ||
          rawMsg.toLowerCase().includes('passphrase')

        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' })
        return res.end(
          JSON.stringify({
            success: false,
            error: isMacOrPassword
              ? 'Senha incorreta do certificado digital A1 ou integridade PKCS#12 corrompida. Verifique a senha cadastrada.'
              : 'Falha ao inicializar contexto TLS com o certificado A1 fornecido.',
            code: 'CERT_INIT_ERROR',
          }),
        )
      }

      const postData = Buffer.from(soapBody, 'utf-8')
      const requestTimeoutMs = Math.max(5000, Math.min(Number(timeout) || 60000, 120000))

      // Cabeçalhos HTTP/1.1 para a SEFAZ
      const requestOptions = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port ? Number(parsedUrl.port) : 443,
        path: parsedUrl.pathname + parsedUrl.search,
        method: 'POST',
        headers: {
          'Content-Type': 'application/soap+xml; charset=utf-8',
          'Content-Length': postData.length,
          Connection: 'close', // Garante HTTP/1.1 limpo
          SOAPAction:
            soapAction ||
            'http://www.portalfiscal.inf.br/nfe/wsdl/NFeDistribuicaoDFe/nfeDistDFeInteresse',
          'User-Agent': 'GestorNFe-Node-mTLS-Proxy/2.0 (OpenSSL)',
        },
        agent: agent,
        timeout: requestTimeoutMs,
      }

      let hasFinished = false
      let sefazReq

      const finishOnce = (statusCode, payloadObj) => {
        if (hasFinished) return
        hasFinished = true
        try {
          if (agent && typeof agent.destroy === 'function') agent.destroy()
        } catch (_) {}
        res.writeHead(statusCode, { 'Content-Type': 'application/json; charset=utf-8' })
        res.end(JSON.stringify(payloadObj))
      }

      try {
        sefazReq = https.request(requestOptions, (sefazRes) => {
          let responseBody = ''
          sefazRes.setEncoding('utf-8')

          sefazRes.on('data', (chunk) => {
            responseBody += chunk
          })

          sefazRes.on('end', () => {
            finishOnce(200, {
              success: true,
              statusCode: sefazRes.statusCode,
              headers: sefazRes.headers,
              body: responseBody,
            })
          })
        })

        sefazReq.on('timeout', () => {
          try {
            sefazReq.destroy()
          } catch (_) {}
          finishOnce(504, {
            success: false,
            error:
              'Timeout na comunicação com a SEFAZ (tempo limite de ' +
              Math.round(requestTimeoutMs / 1000) +
              's excedido sem resposta). O serviço da SEFAZ pode estar instável ou sobrecarregado no momento.',
            code: 'SEFAZ_TIMEOUT',
          })
        })

        sefazReq.on('error', (err) => {
          const rawErr =
            err && (err.message || err.code) ? String(err.message || err.code) : String(err)
          const lower = rawErr.toLowerCase()

          let friendlyMsg = 'Erro na conexão mTLS com a SEFAZ: ' + rawErr
          let code = err.code || 'TLS_CONNECTION_ERROR'
          let httpStatus = 502

          if (
            lower.includes('mac verify failure') ||
            lower.includes('pkcs12') ||
            lower.includes('bad decrypt') ||
            lower.includes('invalid password')
          ) {
            friendlyMsg =
              'Senha do certificado digital A1 incorreta ou arquivo PFX corrompido. Revise a senha salva em Configurações.'
            code = 'CERT_INVALID_PASSPHRASE'
            httpStatus = 400
          } else if (
            lower.includes('handshake') ||
            lower.includes('ssl') ||
            lower.includes('tls') ||
            lower.includes('alert')
          ) {
            friendlyMsg =
              'Falha de handshake TLS com o servidor da SEFAZ (' +
              rawErr +
              '). A SEFAZ pode estar rejeitando a cadeia do certificado A1 ou a negociação de cifras.'
            code = 'TLS_HANDSHAKE_FAILED'
          } else if (lower.includes('econnrefused') || lower.includes('enotfound')) {
            friendlyMsg =
              'Não foi possível alcançar o servidor da SEFAZ (' +
              parsedUrl.hostname +
              '). Verifique a disponibilidade da SEFAZ do seu estado.'
            code = 'SEFAZ_UNREACHABLE'
          } else if (lower.includes('etimedout') || lower.includes('esockettimedout')) {
            friendlyMsg =
              'Tempo esgotado na conexão com o servidor da SEFAZ. O webservice estadual pode estar fora do ar.'
            code = 'SEFAZ_TIMEOUT'
            httpStatus = 504
          }

          finishOnce(httpStatus, {
            success: false,
            error: friendlyMsg,
            code: code,
          })
        })

        sefazReq.write(postData)
        sefazReq.end()
      } catch (execErr) {
        const rawMsg = execErr ? execErr.message || String(execErr) : 'Erro desconhecido'
        const lower = rawMsg.toLowerCase()
        const isPassFail =
          lower.includes('mac') ||
          lower.includes('pkcs12') ||
          lower.includes('password') ||
          lower.includes('decrypt')

        finishOnce(isPassFail ? 400 : 500, {
          success: false,
          error: isPassFail
            ? 'Senha do certificado digital A1 incorreta ou integridade inválida.'
            : 'Falha interna ao inicializar túnel mTLS: ' + rawMsg,
          code: isPassFail ? 'CERT_INVALID_PASSPHRASE' : 'INTERNAL_PROXY_ERROR',
        })
      }
    })
  })
}

// Permite execução direta via CLI: `node pocketbase/sefaz-proxy-server.cjs`
if (require.main === module) {
  const server = createProxyServer()
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`[SEFAZ mTLS Proxy] Servidor ativo e ouvindo em http://0.0.0.0:${PORT}`)
    console.log(
      `[SEFAZ mTLS Proxy] Autenticação x-proxy-secret: ${PROXY_SECRET ? 'Habilitada' : 'Desabilitada (livre)'}`,
    )
  })
}

module.exports = {
  createProxyServer,
  PORT,
  PROXY_SECRET,
}
