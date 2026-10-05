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

// Rate limiting simples em memória (30 requisições / minuto por IP)
const rateLimitMap = new Map()
const RATE_LIMIT_WINDOW_MS = 60 * 1000
const RATE_LIMIT_MAX_REQUESTS = 30

// Limpeza periódica do mapa de rate limiting a cada 5 minutos
const rateLimitCleanupInterval = setInterval(
  () => {
    const now = Date.now()
    for (const [ip, data] of rateLimitMap.entries()) {
      if (now > data.resetAt) {
        rateLimitMap.delete(ip)
      }
    }
  },
  5 * 60 * 1000,
)
if (rateLimitCleanupInterval.unref) rateLimitCleanupInterval.unref()

/**
 * Comparação em tempo constante de duas strings para prevenir timing attacks.
 */
function safeTimingCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false
  const bufA = Buffer.from(a, 'utf-8')
  const bufB = Buffer.from(b, 'utf-8')
  if (bufA.length !== bufB.length) {
    // Garante tempo de comparação equivalente para comprimentos diferentes
    crypto.timingSafeEqual(bufA, bufA)
    return false
  }
  return crypto.timingSafeEqual(bufA, bufB)
}

/**
 * Allowlist estrita de domínios oficiais da SEFAZ para NFe / DFe.
 * Impede que o proxy seja utilizado como relay aberto para qualquer destino arbitrário da internet.
 */
const ALLOWED_SEFAZ_HOST_SUFFIXES = [
  '.fazenda.gov.br', // Ambiente Nacional (www1.nfe.fazenda.gov.br, hom.nfe.fazenda.gov.br, etc.)
  '.sefaz.sp.gov.br', // SEFAZ São Paulo (nfe.fazenda.sp.gov.br / sefaz.sp.gov.br)
  '.fazenda.sp.gov.br',
  '.fazenda.pr.gov.br', // SEFAZ Paraná
  '.sefa.pa.gov.br', // SEFAZ Pará
  '.sefaz.rs.gov.br', // SEFAZ Rio Grande do Sul (SVRS)
  '.sefaz.mg.gov.br', // SEFAZ Minas Gerais
  '.sefaz.ba.gov.br', // SEFAZ Bahia
  '.sefaz.go.gov.br', // SEFAZ Goiás
  '.sefaz.mt.gov.br', // SEFAZ Mato Grosso
  '.sefaz.ms.gov.br', // SEFAZ Mato Grosso do Sul
  '.sefaz.ce.gov.br', // SEFAZ Ceará
  '.sefaz.pe.gov.br', // SEFAZ Pernambuco
  '.sefazvirtual.fazenda.gov.br', // SVAN
]

const ALLOWED_EXACT_HOSTS = new Set([
  'www1.nfe.fazenda.gov.br',
  'hom.nfe.fazenda.gov.br',
  'nfe.fazenda.gov.br',
  'hom1.nfe.fazenda.gov.br',
  'nfe.fazenda.sp.gov.br',
  'homologacao.nfe.fazenda.sp.gov.br',
  'nfe.sefaz.rs.gov.br',
  'nfe-homologacao.sefaz.rs.gov.br',
  'nfe.fazenda.pr.gov.br',
  'homologacao.nfe.fazenda.pr.gov.br',
  'nfe.sefaz.ba.gov.br',
  'hnfe.sefaz.ba.gov.br',
  'nfe.sefaz.go.gov.br',
  'homolog.sefaz.go.gov.br',
  'nfe.sefaz.mg.gov.br',
  'hnfe.fazenda.mg.gov.br',
  'nfe.sefaz.mt.gov.br',
  'homologacao.sefaz.mt.gov.br',
  'nfe.sefaz.ms.gov.br',
  'hom.nfe.sefaz.ms.gov.br',
])

function isAllowedSefazHost(hostname) {
  if (!hostname || typeof hostname !== 'string') return false
  const host = hostname.toLowerCase().trim()

  if (ALLOWED_EXACT_HOSTS.has(host)) return true

  for (const suffix of ALLOWED_SEFAZ_HOST_SUFFIXES) {
    if (host.endsWith(suffix)) {
      return true
    }
  }

  return false
}

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

    // Healthcheck endpoint mínimo (não expõe detalhes internos sensíveis)
    if (req.method === 'GET' && (req.url === '/' || req.url === '/health')) {
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' })
      return res.end(
        JSON.stringify({
          status: 'ok',
          service: 'sefaz-mtls-proxy',
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

    // Rate limiting em memória por IP (sem dependências externas)
    // Janela deslizante de 60s, até 30 requisições por minuto por IP
    const clientIp =
      (req.headers['x-forwarded-for'] &&
        String(req.headers['x-forwarded-for']).split(',')[0].trim()) ||
      req.socket.remoteAddress ||
      'unknown'
    const nowTs = Date.now()
    const rateWindow = rateLimitMap.get(clientIp)
    if (!rateWindow || nowTs > rateWindow.resetAt) {
      rateLimitMap.set(clientIp, { count: 1, resetAt: nowTs + RATE_LIMIT_WINDOW_MS })
    } else {
      rateWindow.count += 1
      if (rateWindow.count > RATE_LIMIT_MAX_REQUESTS) {
        res.writeHead(429, {
          'Content-Type': 'application/json; charset=utf-8',
          'Retry-After': Math.max(1, Math.ceil((rateWindow.resetAt - nowTs) / 1000)),
        })
        return res.end(
          JSON.stringify({
            success: false,
            error:
              'Limite de requisições excedido. Aguarde alguns instantes antes de tentar novamente.',
            code: 'RATE_LIMIT_EXCEEDED',
          }),
        )
      }
    }

    // Validação de token de segurança compartilhado (quando configurado no servidor)
    // Usa comparação em tempo constante para evitar timing attacks
    if (PROXY_SECRET) {
      const providedSecret = String(
        req.headers['x-proxy-secret'] || req.headers['X-Proxy-Secret'] || '',
      )
      const secretMatches = safeTimingCompare(providedSecret, PROXY_SECRET)
      if (!secretMatches) {
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
        pfxExpectedLength,
        pfxExpectedSha256,
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

      // Decodificação do certificado PFX em Base64 e verificação de integridade no transporte
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
              'Arquivo do certificado ilegível ou corrompido no transporte. Formato Base64 inválido.',
            code: 'CERT_CORRUPT',
            bytesRecebidos: 0,
            bytesEsperados: typeof pfxExpectedLength === 'number' ? pfxExpectedLength : null,
            matchChecksum: false,
          }),
        )
      }

      const receivedByteLength = pfxBuffer.length
      const receivedSha256 = crypto.createHash('sha256').update(pfxBuffer).digest('hex')
      let matchChecksum = true

      if (
        pfxExpectedLength &&
        typeof pfxExpectedLength === 'number' &&
        pfxExpectedLength !== receivedByteLength
      ) {
        matchChecksum = false
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' })
        return res.end(
          JSON.stringify({
            success: false,
            error: `Arquivo do certificado ilegível ou corrompido no transporte (recebidos ${receivedByteLength} bytes, esperados ${pfxExpectedLength} bytes).`,
            code: 'CERT_CORRUPT',
            bytesRecebidos: receivedByteLength,
            bytesEsperados: pfxExpectedLength,
            matchChecksum: false,
          }),
        )
      }

      if (pfxExpectedSha256 && typeof pfxExpectedSha256 === 'string') {
        if (receivedSha256.toLowerCase() !== pfxExpectedSha256.toLowerCase()) {
          matchChecksum = false
          res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' })
          return res.end(
            JSON.stringify({
              success: false,
              error: `Arquivo do certificado ilegível ou corrompido no transporte (divergência de checksum SHA-256).`,
              code: 'CERT_CORRUPT',
              bytesRecebidos: receivedByteLength,
              bytesEsperados: pfxExpectedLength || receivedByteLength,
              matchChecksum: false,
            }),
          )
        }
      }

      // Verificação estrutural do cabeçalho ASN.1 DER (PKCS#12 / PFX)
      // Todo arquivo DER PKCS#12 válido começa com SEQUENCE (0x30) e tem tamanho DER coerente
      const isDerSequence = pfxBuffer[0] === 0x30
      if (!isDerSequence) {
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' })
        return res.end(
          JSON.stringify({
            success: false,
            error: `Arquivo do certificado ilegível ou corrompido no transporte: estrutura ASN.1/DER inválida (esperava 0x30 SEQUENCE no início, recebeu 0x${pfxBuffer[0].toString(16)}).`,
            code: 'CERT_CORRUPT',
            bytesRecebidos: receivedByteLength,
            bytesEsperados: pfxExpectedLength || receivedByteLength,
            matchChecksum: matchChecksum,
          }),
        )
      }

      // Verificação de tamanho declarado no cabeçalho DER para detectar truncamento
      let derDeclaredLength = 0
      const secondByte = pfxBuffer[1]
      let derHeaderOffset = 2
      if (secondByte < 0x80) {
        derDeclaredLength = secondByte
      } else {
        const numLenBytes = secondByte & 0x7f
        derHeaderOffset = 2 + numLenBytes
        if (numLenBytes <= 4 && pfxBuffer.length >= derHeaderOffset) {
          for (let i = 0; i < numLenBytes; i++) {
            derDeclaredLength = (derDeclaredLength << 8) | pfxBuffer[2 + i]
          }
        }
      }

      if (derDeclaredLength > 0) {
        const totalExpectedDer = derHeaderOffset + derDeclaredLength
        if (pfxBuffer.length < totalExpectedDer) {
          res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' })
          return res.end(
            JSON.stringify({
              success: false,
              error: `Arquivo do certificado ilegível ou corrompido no transporte: truncado (${pfxBuffer.length} bytes recebidos vs ${totalExpectedDer} bytes declarados na estrutura DER).`,
              code: 'CERT_CORRUPT',
              bytesRecebidos: receivedByteLength,
              bytesEsperados: totalExpectedDer,
              matchChecksum: false,
            }),
          )
        }
      }

      // Validação do endpoint de destino (protocolo HTTPS e ALLOWLIST rígida de domínios SEFAZ)
      let parsedUrl
      try {
        parsedUrl = new url.URL(targetUrl)
        if (parsedUrl.protocol !== 'https:') {
          res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' })
          return res.end(
            JSON.stringify({
              success: false,
              error: 'Apenas endpoints seguros (HTTPS) são aceitos para comunicação com a SEFAZ.',
            }),
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

      // Restrição de segurança: o proxy só pode se comunicar com servidores oficiais da SEFAZ
      if (!isAllowedSefazHost(parsedUrl.hostname)) {
        res.writeHead(403, { 'Content-Type': 'application/json; charset=utf-8' })
        return res.end(
          JSON.stringify({
            success: false,
            error:
              'Acesso negado: o destino solicitado não pertence à lista de webservices oficiais autorizados da SEFAZ.',
            code: 'DESTINATION_NOT_ALLOWED',
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
        const lowerMsg = rawMsg.toLowerCase()
        const isMacOrPassword =
          lowerMsg.includes('mac') ||
          lowerMsg.includes('password') ||
          lowerMsg.includes('passphrase') ||
          lowerMsg.includes('bad decrypt')

        const isCorruptFormat =
          lowerMsg.includes('asn1') ||
          lowerMsg.includes('der') ||
          lowerMsg.includes('nested asn1') ||
          lowerMsg.includes('header too long') ||
          lowerMsg.includes('length too long') ||
          lowerMsg.includes('wrong tag')

        if (isCorruptFormat) {
          res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' })
          return res.end(
            JSON.stringify({
              success: false,
              error: `Arquivo do certificado ilegível ou corrompido no transporte (${receivedByteLength} bytes recebidos).`,
              code: 'CERT_CORRUPT',
              bytesRecebidos: receivedByteLength,
              bytesEsperados: pfxExpectedLength || receivedByteLength,
              matchChecksum: matchChecksum,
            }),
          )
        }

        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' })
        return res.end(
          JSON.stringify({
            success: false,
            error: isMacOrPassword
              ? 'Senha do certificado incorreta'
              : 'Falha ao inicializar contexto TLS com o certificado A1 fornecido.',
            code: isMacOrPassword ? 'CERT_INVALID_PASSPHRASE' : 'CERT_INIT_ERROR',
            bytesRecebidos: receivedByteLength,
            bytesEsperados: pfxExpectedLength || receivedByteLength,
            matchChecksum: matchChecksum,
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
            lower.includes('bad decrypt') ||
            lower.includes('invalid password')
          ) {
            friendlyMsg = 'Senha do certificado incorreta'
            code = 'CERT_INVALID_PASSPHRASE'
            httpStatus = 400
          } else if (
            lower.includes('asn1') ||
            lower.includes('nested') ||
            lower.includes('wrong tag')
          ) {
            friendlyMsg = `Arquivo do certificado ilegível ou corrompido no transporte (${receivedByteLength} bytes recebidos).`
            code = 'CERT_CORRUPT'
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
            bytesRecebidos: receivedByteLength,
            bytesEsperados: pfxExpectedLength || receivedByteLength,
            matchChecksum: matchChecksum,
          })
        })

        sefazReq.write(postData)
        sefazReq.end()
      } catch (execErr) {
        const rawMsg = execErr ? execErr.message || String(execErr) : 'Erro desconhecido'
        const lower = rawMsg.toLowerCase()
        const isPassFail =
          lower.includes('mac') || lower.includes('password') || lower.includes('decrypt')

        const isCorrupt =
          lower.includes('asn1') || lower.includes('der') || lower.includes('wrong tag')

        finishOnce(isPassFail || isCorrupt ? 400 : 500, {
          success: false,
          error: isPassFail
            ? 'Senha do certificado incorreta'
            : isCorrupt
              ? `Arquivo do certificado ilegível ou corrompido no transporte (${receivedByteLength} bytes recebidos).`
              : 'Falha interna ao inicializar túnel mTLS: ' + rawMsg,
          code: isPassFail
            ? 'CERT_INVALID_PASSPHRASE'
            : isCorrupt
              ? 'CERT_CORRUPT'
              : 'INTERNAL_PROXY_ERROR',
          bytesRecebidos: receivedByteLength,
          bytesEsperados: pfxExpectedLength || receivedByteLength,
          matchChecksum: matchChecksum,
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
