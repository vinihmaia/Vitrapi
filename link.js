/* =================== VITRAPI · API de links carimbados ===================
   POST /api/link
   - acao "assinar":  { acao, senha, dados } → { sig }   (só com a senha do Vinicius)
   - acao "conferir": { acao, dados, sig }  → { ok }    (qualquer pessoa pode conferir)
   O segredo e a senha ficam nas variáveis da Vercel, nunca neste arquivo. */
const crypto = require('crypto');

const SEGREDO = process.env.LINKS_SEGREDO || '';
const SENHA = process.env.LINKS_SENHA || '';
const CAMPOS = ['tipo', 'servico', 'valor', 'forma', 'prazo', 'escopo', 'ref'];

/* Os dados viram sempre o mesmo texto, na mesma ordem, para o carimbo bater */
const texto = d => JSON.stringify(CAMPOS.map(k => String(d && d[k] != null ? d[k] : '')));
const carimbo = d => crypto.createHmac('sha256', SEGREDO).update(texto(d)).digest('base64url').slice(0, 22);

/* Compara sem "vazar" pelo tempo de resposta quantas letras acertou */
function iguais(a, b) {
  const x = crypto.createHash('sha256').update(String(a)).digest();
  const y = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
}

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return res.status(405).json({ erro: 'Use POST.' });
  if (SEGREDO.length < 32 || SENHA.length < 12) return res.status(500).json({ erro: 'API sem configuração.' });

  let corpo = req.body || {};
  if (typeof corpo === 'string') { try { corpo = JSON.parse(corpo || '{}'); } catch (e) { return res.status(400).json({ erro: 'Pedido inválido.' }); } }
  const dados = corpo.dados || {};
  if (JSON.stringify(dados).length > 4000) return res.status(413).json({ erro: 'Dados grandes demais.' });

  if (corpo.acao === 'assinar') {
    if (!iguais(corpo.senha || '', SENHA)) {
      await new Promise(r => setTimeout(r, 800)); /* atrasa quem tenta adivinhar a senha */
      return res.status(401).json({ erro: 'Senha incorreta.' });
    }
    return res.status(200).json({ sig: carimbo(dados) });
  }
  if (corpo.acao === 'conferir') return res.status(200).json({ ok: iguais(corpo.sig || '', carimbo(dados)) });
  return res.status(400).json({ erro: 'Ação desconhecida.' });
};