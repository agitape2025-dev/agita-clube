/* =========================================================================
   AGITA — API (Cloudflare Pages Functions + D1)
   Todas as rotas ficam sob /api/... e caem neste arquivo (rota "catch-all").
   O binding D1 se chama "DB" (configurado no wrangler.toml).
   ========================================================================= */

const DURACAO_SESSAO_MS = 1000 * 60 * 60 * 24 * 7; // 7 dias

// ---------------------------------------------------------------------------
// Helpers genéricos
// ---------------------------------------------------------------------------
function json(dados, status = 200, headersExtra = {}) {
  return new Response(JSON.stringify(dados), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...headersExtra }
  });
}
function erro(mensagem, status = 400) {
  return json({ erro: mensagem }, status);
}
function gerarId(prefixo) {
  return prefixo + '_' + crypto.randomUUID().replace(/-/g, '').slice(0, 16);
}
function bytesParaHex(bytes) {
  return [...new Uint8Array(bytes)].map(b => b.toString(16).padStart(2, '0')).join('');
}
function hexParaBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}
async function calcularHash(senha, saltBytes) {
  const enc = new TextEncoder();
  const chave = await crypto.subtle.importKey('raw', enc.encode(senha), { name: 'PBKDF2' }, false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: saltBytes, iterations: 100000, hash: 'SHA-256' },
    chave, 256
  );
  return bytesParaHex(bits);
}
async function gerarHashSenha(senha) {
  const saltBytes = crypto.getRandomValues(new Uint8Array(16));
  const hashHex = await calcularHash(senha, saltBytes);
  return { hash: hashHex, salt: bytesParaHex(saltBytes) };
}
async function verificarSenha(senha, hashHex, saltHex) {
  const calculado = await calcularHash(senha, hexParaBytes(saltHex));
  return calculado === hashHex;
}
function lerCookie(request, nome) {
  const cabecalho = request.headers.get('Cookie') || '';
  const partes = cabecalho.split(';').map(p => p.trim());
  for (const parte of partes) {
    if (parte.startsWith(nome + '=')) return decodeURIComponent(parte.slice(nome.length + 1));
  }
  return null;
}
function cookieSessao(token, maxAgeSegundos) {
  return `agita_sessao=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAgeSegundos}`;
}
function cookieLimpar() {
  return `agita_sessao=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;
}

// Busca o usuário logado a partir do cookie de sessão. Retorna null se não houver sessão válida.
async function usuarioDaSessao(request, env) {
  const token = lerCookie(request, 'agita_sessao');
  if (!token) return null;
  const sessao = await env.DB.prepare(
    `SELECT s.usuario_id, s.expira_em, u.id, u.usuario, u.nome, u.papel, u.precisa_trocar_senha
     FROM sessoes s JOIN usuarios u ON u.id = s.usuario_id
     WHERE s.token = ?`
  ).bind(token).first();
  if (!sessao) return null;
  if (new Date(sessao.expira_em) < new Date()) return null;
  return {
    id: sessao.id,
    usuario: sessao.usuario,
    nome: sessao.nome,
    papel: sessao.papel,
    precisaTrocarSenha: !!sessao.precisa_trocar_senha
  };
}

// ---------------------------------------------------------------------------
// Roteador principal — todas as chamadas a /api/* passam por aqui
// ---------------------------------------------------------------------------
export async function onRequest(context) {
  const { request, env, params } = context;
  const rota = params.route || []; // ex: /api/atletas/123 -> ['atletas', '123']
  const metodo = request.method;

  try {
    // ---------- rotas públicas (não exigem login) ----------
    if (rota[0] === 'login' && metodo === 'POST') return await tratarLogin(request, env);

    // todas as demais rotas exigem sessão válida
    const usuario = await usuarioDaSessao(request, env);
    if (!usuario) return erro('Não autenticado.', 401);

    if (rota[0] === 'logout' && metodo === 'POST') return await tratarLogout(request, env);
    if (rota[0] === 'sessao' && metodo === 'GET') return json({ usuario });
    if (rota[0] === 'trocar-senha' && metodo === 'POST') return await tratarTrocarSenha(request, env, usuario);
    if (rota[0] === 'resumo' && metodo === 'GET') return await tratarResumo(env, usuario);

    if (rota[0] === 'atletas') return await tratarAtletas(request, env, usuario, rota, metodo);
    if (rota[0] === 'documentos') return await tratarDocumentos(request, env, usuario, rota, metodo);
    if (rota[0] === 'pagamentos') return await tratarPagamentos(request, env, usuario, rota, metodo);
    if (rota[0] === 'eventos') return await tratarEventos(request, env, usuario, rota, metodo);
    if (rota[0] === 'avisos') return await tratarAvisos(request, env, usuario, rota, metodo);
    if (rota[0] === 'usuarios') return await tratarUsuarios(request, env, usuario, rota, metodo);

    return erro('Rota não encontrada.', 404);
  } catch (e) {
    return erro('Erro interno: ' + e.message, 500);
  }
}

function exigirAdmin(usuario) {
  if (usuario.papel !== 'admin') return erro('Apenas administradores podem fazer isso.', 403);
  return null;
}
// Admin e técnicas têm acesso à operação do clube (atletas, documentos, pagamentos,
// calendário, avisos) — só a gestão de Usuários fica exclusiva do admin (exigirAdmin acima).
function exigirEquipe(usuario) {
  if (usuario.papel === 'usuario') return erro('Você não tem permissão para fazer isso.', 403);
  return null;
}

// ---------------------------------------------------------------------------
// LOGIN / SESSÃO
// ---------------------------------------------------------------------------
async function tratarLogin(request, env) {
  const corpo = await request.json().catch(() => ({}));
  const usuarioLogin = (corpo.usuario || '').trim();
  const senha = corpo.senha || '';
  if (!usuarioLogin || !senha) return erro('Informe usuário e senha.');

  const u = await env.DB.prepare(`SELECT * FROM usuarios WHERE usuario = ? COLLATE NOCASE`).bind(usuarioLogin).first();
  if (!u) return erro('Usuário ou senha incorretos.', 401);

  const ok = await verificarSenha(senha, u.senha_hash, u.senha_salt);
  if (!ok) return erro('Usuário ou senha incorretos.', 401);

  const token = crypto.randomUUID() + crypto.randomUUID();
  const agora = new Date();
  const expira = new Date(agora.getTime() + DURACAO_SESSAO_MS);
  await env.DB.prepare(`INSERT INTO sessoes (token, usuario_id, criado_em, expira_em) VALUES (?,?,?,?)`)
    .bind(token, u.id, agora.toISOString(), expira.toISOString()).run();
  await env.DB.prepare(`UPDATE usuarios SET ultimo_acesso = ? WHERE id = ?`).bind(agora.toISOString(), u.id).run();

  return json(
    { usuario: { id: u.id, usuario: u.usuario, nome: u.nome, papel: u.papel, precisaTrocarSenha: !!u.precisa_trocar_senha } },
    200,
    { 'Set-Cookie': cookieSessao(token, DURACAO_SESSAO_MS / 1000) }
  );
}
async function tratarLogout(request, env) {
  const token = lerCookie(request, 'agita_sessao');
  if (token) await env.DB.prepare(`DELETE FROM sessoes WHERE token = ?`).bind(token).run();
  return json({ ok: true }, 200, { 'Set-Cookie': cookieLimpar() });
}
async function tratarTrocarSenha(request, env, usuario) {
  const corpo = await request.json().catch(() => ({}));
  const novaSenha = corpo.novaSenha || '';
  if (novaSenha.length < 6) return erro('A nova senha precisa ter pelo menos 6 caracteres.');
  const { hash, salt } = await gerarHashSenha(novaSenha);
  await env.DB.prepare(`UPDATE usuarios SET senha_hash=?, senha_salt=?, precisa_trocar_senha=0 WHERE id=?`)
    .bind(hash, salt, usuario.id).run();
  return json({ ok: true });
}

// ---------------------------------------------------------------------------
// RESUMO (dashboard)
// ---------------------------------------------------------------------------
async function tratarResumo(env, usuario) {
  const hojeISO = new Date().toISOString().slice(0, 10);
  const [{ total: eventosFuturos }] = (await env.DB.prepare(
    `SELECT COUNT(*) as total FROM eventos WHERE fim >= ?`
  ).bind(hojeISO).all()).results;
  const [{ total: avisos }] = (await env.DB.prepare(`SELECT COUNT(*) as total FROM avisos_publicados`).all()).results;

  const resumo = { eventosFuturos, avisosPublicados: avisos };

  if (usuario.papel === 'admin' || usuario.papel === 'tecnica') {
    const [{ total: atletas }] = (await env.DB.prepare(`SELECT COUNT(*) as total FROM atletas`).all()).results;
    const [{ total: documentos }] = (await env.DB.prepare(`SELECT COUNT(*) as total FROM documentos`).all()).results;
    const [{ total: pendentes }] = (await env.DB.prepare(`SELECT COUNT(*) as total FROM pagamentos WHERE status='pendente'`).all()).results;
    Object.assign(resumo, { atletas, documentos, pagamentosPendentes: pendentes });
  }
  if (usuario.papel === 'admin') {
    const [{ total: usuarios }] = (await env.DB.prepare(`SELECT COUNT(*) as total FROM usuarios`).all()).results;
    Object.assign(resumo, { usuarios });
  }
  return json(resumo);
}

// ---------------------------------------------------------------------------
// ATLETAS (somente admin)
// ---------------------------------------------------------------------------
async function tratarAtletas(request, env, usuario, rota, metodo) {
  const bloqueado = exigirEquipe(usuario);
  if (bloqueado) return bloqueado;
  const id = rota[1];

  if (metodo === 'GET' && !id) {
    const { results } = await env.DB.prepare(`SELECT * FROM atletas ORDER BY nome`).all();
    return json({ atletas: results });
  }
  if (metodo === 'POST' && !id) {
    const c = await request.json();
    if (!c.nome || !c.nome.trim()) return erro('Informe o nome da atleta.');
    const novoId = gerarId('at');
    await env.DB.prepare(
      `INSERT INTO atletas (id, nome, nascimento, categoria, responsavel, telefone, foto) VALUES (?,?,?,?,?,?,?)`
    ).bind(novoId, c.nome.trim(), c.nascimento || null, c.categoria || null, c.responsavel || null, c.telefone || null, c.foto || null).run();
    return json({ id: novoId });
  }
  if (metodo === 'PUT' && id) {
    const c = await request.json();
    if (!c.nome || !c.nome.trim()) return erro('Informe o nome da atleta.');
    await env.DB.prepare(
      `UPDATE atletas SET nome=?, nascimento=?, categoria=?, responsavel=?, telefone=?, foto=? WHERE id=?`
    ).bind(c.nome.trim(), c.nascimento || null, c.categoria || null, c.responsavel || null, c.telefone || null, c.foto || null, id).run();
    return json({ ok: true });
  }
  if (metodo === 'DELETE' && id) {
    await env.DB.prepare(`DELETE FROM atletas WHERE id=?`).bind(id).run();
    await env.DB.prepare(`DELETE FROM documentos WHERE atleta_id=?`).bind(id).run();
    await env.DB.prepare(`DELETE FROM pagamentos WHERE atleta_id=?`).bind(id).run();
    return json({ ok: true });
  }
  return erro('Rota inválida.', 404);
}

// ---------------------------------------------------------------------------
// DOCUMENTOS (somente admin)
// ---------------------------------------------------------------------------
async function tratarDocumentos(request, env, usuario, rota, metodo) {
  const bloqueado = exigirEquipe(usuario);
  if (bloqueado) return bloqueado;
  const id = rota[1];

  if (metodo === 'GET' && !id) {
    const url = new URL(request.url);
    const atletaId = url.searchParams.get('atletaId');
    if (!atletaId) return erro('Informe atletaId.');
    const { results } = await env.DB.prepare(`SELECT * FROM documentos WHERE atleta_id=? ORDER BY data_upload DESC`).bind(atletaId).all();
    return json({ documentos: results });
  }
  if (metodo === 'POST' && !id) {
    const c = await request.json();
    if (!c.atletaId || !c.conteudo) return erro('Dados incompletos.');
    const novoId = gerarId('doc');
    const agora = new Date().toISOString();
    await env.DB.prepare(
      `INSERT INTO documentos (id, atleta_id, tipo, nome_arquivo, conteudo, data_upload) VALUES (?,?,?,?,?,?)`
    ).bind(novoId, c.atletaId, c.tipo || 'Documento', c.nomeArquivo || 'arquivo', c.conteudo, agora).run();
    return json({ id: novoId });
  }
  if (metodo === 'DELETE' && id) {
    await env.DB.prepare(`DELETE FROM documentos WHERE id=?`).bind(id).run();
    return json({ ok: true });
  }
  return erro('Rota inválida.', 404);
}

// ---------------------------------------------------------------------------
// PAGAMENTOS (somente admin)
// ---------------------------------------------------------------------------
async function tratarPagamentos(request, env, usuario, rota, metodo) {
  const bloqueado = exigirEquipe(usuario);
  if (bloqueado) return bloqueado;
  const id = rota[1];

  if (metodo === 'GET' && !id) {
    const { results } = await env.DB.prepare(
      `SELECT p.*, a.nome as atleta_nome FROM pagamentos p LEFT JOIN atletas a ON a.id = p.atleta_id ORDER BY p.status, a.nome`
    ).all();
    return json({ pagamentos: results });
  }
  if (metodo === 'POST' && !id) {
    const c = await request.json();
    if (!c.atletaId) return erro('Informe a atleta.');
    const novoId = gerarId('pg');
    await env.DB.prepare(
      `INSERT INTO pagamentos (id, atleta_id, descricao, valor, status) VALUES (?,?,?,?, 'pendente')`
    ).bind(novoId, c.atletaId, c.descricao || 'Inscrição', c.valor || null).run();
    return json({ id: novoId });
  }
  if (metodo === 'PATCH' && id) {
    const atual = await env.DB.prepare(`SELECT status FROM pagamentos WHERE id=?`).bind(id).first();
    if (!atual) return erro('Pagamento não encontrado.', 404);
    const novoStatus = atual.status === 'confirmado' ? 'pendente' : 'confirmado';
    await env.DB.prepare(`UPDATE pagamentos SET status=? WHERE id=?`).bind(novoStatus, id).run();
    return json({ status: novoStatus });
  }
  if (metodo === 'DELETE' && id) {
    await env.DB.prepare(`DELETE FROM pagamentos WHERE id=?`).bind(id).run();
    return json({ ok: true });
  }
  return erro('Rota inválida.', 404);
}

// ---------------------------------------------------------------------------
// EVENTOS (visualização liberada a todos; criar/excluir só admin)
// ---------------------------------------------------------------------------
async function tratarEventos(request, env, usuario, rota, metodo) {
  const id = rota[1];

  if (metodo === 'GET' && !id) {
    const { results } = await env.DB.prepare(`SELECT * FROM eventos ORDER BY inicio`).all();
    return json({ eventos: results });
  }
  if (metodo === 'POST' && !id) {
    const bloqueado = exigirEquipe(usuario);
    if (bloqueado) return bloqueado;
    const c = await request.json();
    if (!c.titulo || !c.inicio) return erro('Preencha título e data de início.');
    const fim = c.fim || c.inicio;
    if (fim < c.inicio) return erro('A data de término não pode ser antes da data de início.');
    const novoId = gerarId('ev');
    await env.DB.prepare(`INSERT INTO eventos (id, titulo, inicio, fim, tipo) VALUES (?,?,?,?,?)`)
      .bind(novoId, c.titulo.trim(), c.inicio, fim, c.tipo || 'Outro').run();
    return json({ id: novoId });
  }
  if (metodo === 'DELETE' && id) {
    const bloqueado = exigirEquipe(usuario);
    if (bloqueado) return bloqueado;
    await env.DB.prepare(`DELETE FROM eventos WHERE id=?`).bind(id).run();
    return json({ ok: true });
  }
  return erro('Rota inválida.', 404);
}

// ---------------------------------------------------------------------------
// AVISOS PUBLICADOS (visualização liberada a todos; publicar/excluir só admin)
// ---------------------------------------------------------------------------
async function tratarAvisos(request, env, usuario, rota, metodo) {
  const id = rota[1];

  if (metodo === 'GET' && !id) {
    const { results } = await env.DB.prepare(`SELECT * FROM avisos_publicados ORDER BY criado_em DESC`).all();
    return json({ avisos: results });
  }
  if (metodo === 'POST' && !id) {
    const bloqueado = exigirEquipe(usuario);
    if (bloqueado) return bloqueado;
    const c = await request.json();
    if (!c.imagem) return erro('Banner ausente.');
    const novoId = gerarId('av');
    const agora = new Date().toISOString();
    await env.DB.prepare(`INSERT INTO avisos_publicados (id, tipo, titulo, imagem, criado_em) VALUES (?,?,?,?,?)`)
      .bind(novoId, c.tipo || 'geral', c.titulo || 'Aviso', c.imagem, agora).run();
    return json({ id: novoId });
  }
  if (metodo === 'DELETE' && id) {
    const bloqueado = exigirEquipe(usuario);
    if (bloqueado) return bloqueado;
    await env.DB.prepare(`DELETE FROM avisos_publicados WHERE id=?`).bind(id).run();
    return json({ ok: true });
  }
  return erro('Rota inválida.', 404);
}

// ---------------------------------------------------------------------------
// USUÁRIOS (somente admin)
// ---------------------------------------------------------------------------
async function tratarUsuarios(request, env, usuario, rota, metodo) {
  const bloqueado = exigirAdmin(usuario);
  if (bloqueado) return bloqueado;
  const id = rota[1];
  const acao = rota[2]; // ex: /api/usuarios/u2/resetar-senha

  if (metodo === 'GET' && !id) {
    const { results } = await env.DB.prepare(
      `SELECT id, usuario, nome, papel, precisa_trocar_senha, ultimo_acesso FROM usuarios ORDER BY nome`
    ).all();
    return json({ usuarios: results });
  }
  if (metodo === 'POST' && !id) {
    const c = await request.json();
    if (!c.nome || !c.usuario) return erro('Preencha todos os campos.');
    const existente = await env.DB.prepare(`SELECT id FROM usuarios WHERE usuario=? COLLATE NOCASE`).bind(c.usuario).first();
    if (existente) return erro('Este usuário já existe.');
    const { hash, salt } = await gerarHashSenha('Agita@123');
    const novoId = gerarId('us');
    const papeisValidos = ['admin', 'tecnica', 'usuario'];
    const papel = papeisValidos.includes(c.papel) ? c.papel : 'usuario';
    await env.DB.prepare(
      `INSERT INTO usuarios (id, usuario, senha_hash, senha_salt, nome, papel, precisa_trocar_senha, ultimo_acesso) VALUES (?,?,?,?,?,?,1,NULL)`
    ).bind(novoId, c.usuario.trim(), hash, salt, c.nome.trim(), papel).run();
    return json({ id: novoId });
  }
  if (metodo === 'POST' && id && acao === 'resetar-senha') {
    const { hash, salt } = await gerarHashSenha('Agita@123');
    await env.DB.prepare(`UPDATE usuarios SET senha_hash=?, senha_salt=?, precisa_trocar_senha=1 WHERE id=?`)
      .bind(hash, salt, id).run();
    return json({ ok: true });
  }
  if (metodo === 'DELETE' && id) {
    if (id === usuario.id) return erro('Você não pode excluir o usuário com o qual está logado.');
    const [{ total }] = (await env.DB.prepare(`SELECT COUNT(*) as total FROM usuarios`).all()).results;
    if (total <= 1) return erro('É preciso manter ao menos um usuário.');
    await env.DB.prepare(`DELETE FROM usuarios WHERE id=?`).bind(id).run();
    return json({ ok: true });
  }
  return erro('Rota inválida.', 404);
}
