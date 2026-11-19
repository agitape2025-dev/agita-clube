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
    if (rota[0] === 'push') return await tratarPush(request, env, usuario, rota, metodo);
    if (rota[0] === 'avisos') return await tratarAvisos(request, env, usuario, rota, metodo);
    if (rota[0] === 'usuarios') return await tratarUsuarios(request, env, usuario, rota, metodo);
    if (rota[0] === 'mensalidades') return await tratarMensalidades(request, env, usuario, rota, metodo);
    if (rota[0] === 'valores-mensalidade') return await tratarValoresMensalidade(request, env, usuario, rota, metodo);
    if (rota[0] === 'chamada') return await tratarChamada(request, env, usuario, rota, metodo);
    if (rota[0] === 'reuniao') return await tratarReuniao(request, env, usuario, rota, metodo);
    if (rota[0] === 'taxas') return await tratarTaxas(request, env, usuario, rota, metodo);
    if (rota[0] === 'despesas') return await tratarDespesas(request, env, usuario, rota, metodo);
    if (rota[0] === 'financeiro-resumo' && metodo === 'GET') return await tratarFinanceiroResumo(env, usuario);

    return erro('Rota não encontrada.', 404);
  } catch (e) {
    return erro('Erro interno: ' + e.message, 500);
  }
}

// ---------------------------------------------------------------------------
// Reunião da diretoria (pauta interativa, sincronizada por polling)
// ---------------------------------------------------------------------------
let reuniaoPronta = false;
function reuniaoPadraoPais() {
  const def = [
    ['Boas-vindas e apresentação da equipe', '👋', ['Apresentação da diretoria e das técnicas', 'Nossa mascote']],
    ['Balanço de 2026', '🏆', ['Conquistas das atletas', 'Apresentações e competições']],
    ['Festival 2026', '🎪', ['Local e horário', 'Lembrancinhas', 'Participação das famílias']],
    ['Séries 2027', '🏅', ['Cronograma de montagem', 'Valores']],
    ['Mensalidades e pagamentos', '💳', ['Valores para 2027', 'Datas de vencimento', 'Formas de pagamento']],
    ['Rotina e convivência', '📋', ['Horários e pontualidade', 'Uniforme', 'Faltas e justificativas']],
    ['Comunicação com as famílias', '📣', ['Portal e aplicativo do AGITA', 'Avisos e WhatsApp']],
    ['Dúvidas e sugestões', '💬', ['Espaço aberto para as famílias']]
  ];
  return {
    titulo: 'Reunião com os Pais AGITA',
    itens: def.map((d, i) => ({
      id: 'i' + (i + 1), titulo: d[0], icone: d[1], nota: '',
      subitens: d[2].map((t, j) => ({ id: 'i' + (i + 1) + 's' + (j + 1), texto: t, status: 'pendente', responsavel: '', decisao: '' }))
    })),
    papeis: []
  };
}
function reuniaoPadrao(tipo) {
  if (tipo === 'pais') return reuniaoPadraoPais();
  const def = [
    ['Festival 2026', '🎪', ['Local', 'Horário', 'Lembrancinhas']],
    ['Comunicação', '📣', ['Meios de comunicação', 'Página do AGITA', 'WhatsApp']],
    ['Séries 2027', '🏅', ['Definição dos valores', 'Cronograma de montagem']],
    ['Planejamento das aulas – 2027', '🤸', ['Preparação física', 'Ballet', 'Cronograma de treinamentos: treinos específicos para atletas que precisam', 'Datas das competições', 'Ausência das técnicas: datas de viagem e cobertura do clube (ex.: só a Renata)']],
    ['Parcerias', '🤝', ['Elaboração do portfólio AGITA', 'Psicólogo', 'Nutricionistas', 'Fisioterapeuta']],
    ['Turma da manhã – Escolinha', '🌅', ['Avaliação da viabilidade de continuidade']],
    ['Equipe e Recursos Humanos', '👥', ['Contratação de mais uma assistente', 'Reajuste salarial: Kaylane e Isabel', 'Reajuste de Renata', 'Plano de saúde para Kaylane']]
  ];
  return {
    titulo: 'Reunião Diretoria AGITA',
    itens: def.map((d, i) => ({
      id: 'i' + (i + 1), titulo: d[0], icone: d[1], nota: '',
      subitens: d[2].map((t, j) => ({ id: 'i' + (i + 1) + 's' + (j + 1), texto: t, status: 'pendente', responsavel: '', decisao: '' }))
    })),
    papeis: []
  };
}
async function tratarReuniao(request, env, usuario, rota, metodo) {
  const tipoReq = new URL(request.url).searchParams.get('tipo') === 'pais' ? 'pais' : 'principal';
  const ehTec = usuario.papel === 'tecnica';
  if (['admin', 'diretoria', 'financeiro'].indexOf(usuario.papel) < 0 && !(ehTec && tipoReq === 'pais')) return erro('Acesso restrito à diretoria.', 403);
  const ehAdm = usuario.papel === 'admin';
  const tipo = new URL(request.url).searchParams.get('tipo') === 'pais' ? 'pais' : 'principal';
  if (!reuniaoPronta) {
    await env.DB.prepare("CREATE TABLE IF NOT EXISTS reuniao_estado (id TEXT PRIMARY KEY, dados TEXT NOT NULL, posicao TEXT NOT NULL, versao INTEGER NOT NULL DEFAULT 1, atualizado_em TEXT)").run();
    await env.DB.prepare("CREATE TABLE IF NOT EXISTS reuniao_notas (id TEXT PRIMARY KEY, tipo TEXT NOT NULL, item_id TEXT NOT NULL, autor TEXT, texto TEXT NOT NULL, criado_em TEXT)").run();
    reuniaoPronta = true;
  }
  let linha = await env.DB.prepare("SELECT * FROM reuniao_estado WHERE id = '" + tipo + "'").first();
  if (!linha) {
    await env.DB.prepare("INSERT OR IGNORE INTO reuniao_estado (id, dados, posicao, versao, atualizado_em) VALUES ('" + tipo + "', ?, ?, 1, ?)")
      .bind(JSON.stringify(reuniaoPadrao(tipo)), JSON.stringify({ s: 0, r: 0 }), new Date().toISOString()).run();
    linha = await env.DB.prepare("SELECT * FROM reuniao_estado WHERE id = '" + tipo + "'").first();
  }
  if (metodo === 'GET') {
    const v = Number(new URL(request.url).searchParams.get('v') || 0);
    if (v === linha.versao) return json({ semMudanca: true, versao: linha.versao, podeEditar: ehAdm });
    const rsNotas = await env.DB.prepare("SELECT id, item_id, autor, texto, criado_em FROM reuniao_notas WHERE tipo = ? ORDER BY criado_em").bind(tipo).all();
    const meuNome = usuario.nome || usuario.email || 'Equipe';
    const notas = (rsNotas.results || []).map(function (n) { return { id: n.id, item_id: n.item_id, autor: n.autor, texto: n.texto, criado_em: n.criado_em, pode_apagar: ehAdm || n.autor === meuNome }; });
    return json({ versao: linha.versao, dados: JSON.parse(linha.dados), posicao: JSON.parse(linha.posicao), podeEditar: ehAdm, podeAnotar: true, notas: notas, atualizadoEm: linha.atualizado_em });
  }
  if (rota[1] === 'nota') {
    if (metodo === 'POST') {
      const corpo = await request.json().catch(() => ({}));
      const texto = String((corpo && corpo.texto) || '').trim().slice(0, 2000);
      const itemId = String((corpo && corpo.itemId) || '').slice(0, 60);
      if (!texto || !itemId) return erro('Escreva a anotação.');
      await env.DB.prepare("INSERT INTO reuniao_notas (id, tipo, item_id, autor, texto, criado_em) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(gerarId('rn'), tipo, itemId, usuario.nome || usuario.email || 'Equipe', texto, new Date().toISOString()).run();
    } else if (metodo === 'DELETE') {
      const idNota = new URL(request.url).searchParams.get('id') || '';
      const n = await env.DB.prepare("SELECT autor FROM reuniao_notas WHERE id = ? AND tipo = ?").bind(idNota, tipo).first();
      if (!n) return erro('Anotação não encontrada.', 404);
      if (!ehAdm && n.autor !== (usuario.nome || usuario.email || 'Equipe')) return erro('Você só pode apagar as suas anotações.', 403);
      await env.DB.prepare("DELETE FROM reuniao_notas WHERE id = ?").bind(idNota).run();
    } else {
      return erro('Rota não encontrada.', 404);
    }
    await env.DB.prepare("UPDATE reuniao_estado SET versao = versao + 1 WHERE id = '" + tipo + "'").run();
    const nv = await env.DB.prepare("SELECT versao FROM reuniao_estado WHERE id = '" + tipo + "'").first();
    return json({ ok: true, versao: nv.versao });
  }
  if (!ehAdm) return erro('Apenas o administrador pode alterar a reunião.', 403);
  const agora = new Date().toISOString();
  if (metodo === 'PUT') {
    const corpo = await request.json().catch(() => ({}));
    const dados = corpo && corpo.dados;
    if (!dados || !Array.isArray(dados.itens)) return erro('Dados inválidos.');
    const txt = JSON.stringify(dados);
    if (txt.length > 300000) return erro('Conteúdo grande demais.');
    await env.DB.prepare("UPDATE reuniao_estado SET dados = ?, versao = versao + 1, atualizado_em = ? WHERE id = '" + tipo + "'").bind(txt, agora).run();
  } else if (metodo === 'POST' && rota[1] === 'posicao') {
    const corpo = await request.json().catch(() => ({}));
    const p = corpo && corpo.posicao;
    if (!p) return erro('Posição inválida.');
    const pos = { s: Math.max(0, parseInt(p.s, 10) || 0), r: Math.max(0, parseInt(p.r, 10) || 0) };
    await env.DB.prepare("UPDATE reuniao_estado SET posicao = ?, versao = versao + 1, atualizado_em = ? WHERE id = '" + tipo + "'").bind(JSON.stringify(pos), agora).run();
  } else if (metodo === 'POST' && rota[1] === 'restaurar') {
    await env.DB.prepare("UPDATE reuniao_estado SET dados = ?, posicao = ?, versao = versao + 1, atualizado_em = ? WHERE id = '" + tipo + "'")
      .bind(JSON.stringify(reuniaoPadrao(tipo)), JSON.stringify({ s: 0, r: 0 }), agora).run();
  } else {
    return erro('Rota não encontrada.', 404);
  }
  const nova = await env.DB.prepare("SELECT versao FROM reuniao_estado WHERE id = '" + tipo + "'").first();
  return json({ ok: true, versao: nova.versao });
}

function exigirAdmin(usuario) {
  // Financeiro tem as mesmas funções do Admin (inclusive gestão de Usuários).
  if (usuario.papel !== 'admin' && usuario.papel !== 'financeiro') return erro('Apenas administradores podem fazer isso.', 403);
  return null;
}
// Admin, técnica, diretoria e financeiro têm acesso à operação do clube (atletas, documentos,
// pagamentos, calendário, avisos) — só o papel "usuario" (responsável/família) fica de fora.
function exigirEquipe(usuario) {
  if (usuario.papel === 'usuario') return erro('Você não tem permissão para fazer isso.', 403);
  return null;
}
// Financeiro tem as mesmas funções do Admin, então também pode criar/editar/excluir dados.
function exigirGerenciar(usuario) {
  if (usuario.papel !== 'admin' && usuario.papel !== 'tecnica' && usuario.papel !== 'financeiro') return erro('Você tem acesso apenas para visualização.', 403);
  return null;
}
// Módulo Financeiro (mensalidades, taxas, despesas): só admin e o papel "financeiro"
// têm acesso — nem técnica, nem diretoria, nem usuário comum enxergam esse menu.
function exigirFinanceiro(usuario) {
  if (usuario.papel !== 'admin' && usuario.papel !== 'financeiro') return erro('Você não tem acesso ao módulo financeiro.', 403);
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

  if (usuario.papel === 'admin' || usuario.papel === 'tecnica' || usuario.papel === 'diretoria' || usuario.papel === 'financeiro') {
    const [{ total: atletas }] = (await env.DB.prepare(`SELECT COUNT(*) as total FROM atletas`).all()).results;
    const [{ total: documentos }] = (await env.DB.prepare(`SELECT COUNT(*) as total FROM documentos`).all()).results;
    const [{ total: pendentes }] = (await env.DB.prepare(`SELECT COUNT(*) as total FROM pagamentos WHERE status='pendente'`).all()).results;
    Object.assign(resumo, { atletas, documentos, pagamentosPendentes: pendentes });
  }
  if (usuario.papel === 'admin' || usuario.papel === 'financeiro') {
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
    const bloqueadoEscrita = exigirGerenciar(usuario);
    if (bloqueadoEscrita) return bloqueadoEscrita;
    const c = await request.json();
    if (!c.nome || !c.nome.trim()) return erro('Informe o nome da atleta.');
    const novoId = gerarId('at');
    await env.DB.prepare(
      `INSERT INTO atletas (id, nome, nascimento, categoria, setor, responsavel, telefone, foto) VALUES (?,?,?,?,?,?,?,?)`
    ).bind(novoId, c.nome.trim(), c.nascimento || null, c.categoria || null, c.setor || null, c.responsavel || null, c.telefone || null, c.foto || null).run();
    return json({ id: novoId });
  }
  if (metodo === 'PUT' && id) {
    const bloqueadoEscrita = exigirGerenciar(usuario);
    if (bloqueadoEscrita) return bloqueadoEscrita;
    const c = await request.json();
    if (!c.nome || !c.nome.trim()) return erro('Informe o nome da atleta.');
    await env.DB.prepare(
      `UPDATE atletas SET nome=?, nascimento=?, categoria=?, setor=?, responsavel=?, telefone=?, foto=? WHERE id=?`
    ).bind(c.nome.trim(), c.nascimento || null, c.categoria || null, c.setor || null, c.responsavel || null, c.telefone || null, c.foto || null, id).run();
    return json({ ok: true });
  }
  if (metodo === 'DELETE' && id) {
    const bloqueadoExclusao = exigirGerenciar(usuario);
    if (bloqueadoExclusao) return bloqueadoExclusao;
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
    const bloqueadoEscrita = exigirGerenciar(usuario);
    if (bloqueadoEscrita) return bloqueadoEscrita;
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
    const bloqueadoExclusao = exigirGerenciar(usuario);
    if (bloqueadoExclusao) return bloqueadoExclusao;
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
    const bloqueadoEscrita = exigirGerenciar(usuario);
    if (bloqueadoEscrita) return bloqueadoEscrita;
    const c = await request.json();
    if (!c.atletaId) return erro('Informe a atleta.');
    const novoId = gerarId('pg');
    await env.DB.prepare(
      `INSERT INTO pagamentos (id, atleta_id, descricao, valor, status) VALUES (?,?,?,?, 'pendente')`
    ).bind(novoId, c.atletaId, c.descricao || 'Inscrição', c.valor || null).run();
    return json({ id: novoId });
  }
  if (metodo === 'PATCH' && id) {
    const bloqueadoEscrita = exigirGerenciar(usuario);
    if (bloqueadoEscrita) return bloqueadoEscrita;
    const atual = await env.DB.prepare(`SELECT status FROM pagamentos WHERE id=?`).bind(id).first();
    if (!atual) return erro('Pagamento não encontrado.', 404);
    const novoStatus = atual.status === 'confirmado' ? 'pendente' : 'confirmado';
    await env.DB.prepare(`UPDATE pagamentos SET status=? WHERE id=?`).bind(novoStatus, id).run();
    return json({ status: novoStatus });
  }
  if (metodo === 'DELETE' && id) {
    const bloqueadoExclusao = exigirGerenciar(usuario);
    if (bloqueadoExclusao) return bloqueadoExclusao;
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
    const bloqueado = exigirGerenciar(usuario);
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
  if (metodo === 'PUT' && id) {
    const bloqueado = exigirGerenciar(usuario);
    if (bloqueado) return bloqueado;
    const c = await request.json();
    if (!c.titulo || !c.inicio) return erro('Preencha título e data de início.');
    const fim = c.fim || c.inicio;
    if (fim < c.inicio) return erro('A data de término não pode ser antes da data de início.');
    await env.DB.prepare(`UPDATE eventos SET titulo=?, inicio=?, fim=?, tipo=? WHERE id=?`)
      .bind(c.titulo.trim(), c.inicio, fim, c.tipo || 'Outro', id).run();
    return json({ ok: true });
  }
  if (metodo === 'DELETE' && id) {
    const bloqueado = exigirGerenciar(usuario);
    if (bloqueado) return bloqueado;
    await env.DB.prepare(`DELETE FROM eventos WHERE id=?`).bind(id).run();
    return json({ ok: true });
  }
  return erro('Rota inválida.', 404);
}

// ---------------------------------------------------------------------------
// AVISOS PUBLICADOS (visualização liberada a todos; publicar/excluir só admin)
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// NOTIFICAÇÕES PUSH (Web Push sem conteúdo: o aparelho busca o último aviso ao receber)
// ---------------------------------------------------------------------------
let tabelasPushGarantidas = false;
async function garantirTabelasPush(env) {
  if (tabelasPushGarantidas) return;
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS push_inscricoes (
    id TEXT PRIMARY KEY, usuario_id TEXT, endpoint TEXT NOT NULL UNIQUE, criado_em TEXT
  )`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS configuracoes (chave TEXT PRIMARY KEY, valor TEXT)`).run();
  tabelasPushGarantidas = true;
}
function b64u(buf) {
  let s = '';
  new Uint8Array(buf).forEach(b => { s += String.fromCharCode(b); });
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
// As chaves VAPID são geradas uma única vez pelo próprio servidor e guardadas no D1.
async function obterChavesVapid(env) {
  await garantirTabelasPush(env);
  let row = await env.DB.prepare(`SELECT valor FROM configuracoes WHERE chave='vapid'`).first();
  if (!row) {
    const par = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const privada = await crypto.subtle.exportKey('jwk', par.privateKey);
    const publica = b64u(await crypto.subtle.exportKey('raw', par.publicKey));
    await env.DB.prepare(`INSERT OR IGNORE INTO configuracoes (chave, valor) VALUES ('vapid', ?)`)
      .bind(JSON.stringify({ publica, privada })).run();
    row = await env.DB.prepare(`SELECT valor FROM configuracoes WHERE chave='vapid'`).first();
  }
  return JSON.parse(row.valor);
}
async function jwtVapid(endpoint, chaves) {
  const enc = (o) => b64u(new TextEncoder().encode(JSON.stringify(o)));
  const cab = enc({ typ: 'JWT', alg: 'ES256' });
  const corpo = enc({ aud: new URL(endpoint).origin, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: 'https://agita-clube.pages.dev' });
  const chave = await crypto.subtle.importKey('jwk', chaves.privada, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, chave, new TextEncoder().encode(cab + '.' + corpo));
  return cab + '.' + corpo + '.' + b64u(sig);
}

async function tratarPush(request, env, usuario, rota, metodo) {
  await garantirTabelasPush(env);
  const acao = rota[1];

  if (metodo === 'GET' && acao === 'chave') {
    const chaves = await obterChavesVapid(env);
    return json({ chave: chaves.publica });
  }
  if (metodo === 'POST' && acao === 'inscrever') {
    const c = await request.json();
    if (!c.endpoint || !/^https:\/\//.test(c.endpoint)) return erro('Inscrição inválida.', 400);
    await env.DB.prepare(
      `INSERT INTO push_inscricoes (id, usuario_id, endpoint, criado_em) VALUES (?,?,?,?)
       ON CONFLICT(endpoint) DO UPDATE SET usuario_id = excluded.usuario_id`
    ).bind(gerarId('ps'), usuario.id || null, c.endpoint, new Date().toISOString()).run();
    return json({ ok: true });
  }
  if (metodo === 'POST' && acao === 'cancelar') {
    const c = await request.json();
    if (c.endpoint) await env.DB.prepare(`DELETE FROM push_inscricoes WHERE endpoint=?`).bind(c.endpoint).run();
    return json({ ok: true });
  }
  // Envio em lotes de 40 (limite de subrequisições por chamada): o painel repete até acabar.
  if (metodo === 'POST' && acao === 'enviar') {
    const bloqueado = exigirGerenciar(usuario);
    if (bloqueado) return bloqueado;
    const c = await request.json().catch(() => ({}));
    const desloc = Math.max(0, parseInt(c.deslocamento, 10) || 0);
    const LOTE = 40;
    const chaves = await obterChavesVapid(env);
    const papeis = PAPEIS_DO_PUBLICO[c.publico] || null;
    const filtroPush = papeis ? ' WHERE usuario_id IN (SELECT id FROM usuarios WHERE papel IN (' + papeis.map(() => '?').join(',') + '))' : '';
    const bindsPush = papeis || [];
    const { results: tot } = await env.DB.prepare('SELECT COUNT(*) AS n FROM push_inscricoes' + filtroPush).bind(...bindsPush).all();
    const total = tot[0]?.n || 0;
    const { results } = await env.DB.prepare('SELECT id, endpoint FROM push_inscricoes' + filtroPush + ' ORDER BY id LIMIT ? OFFSET ?').bind(...bindsPush, LOTE, desloc).all();
    let enviadas = 0;
    const remover = [];
    await Promise.all(results.map(async (s) => {
      try {
        const jwt = await jwtVapid(s.endpoint, chaves);
        const r = await fetch(s.endpoint, {
          method: 'POST',
          headers: { Authorization: 'vapid t=' + jwt + ', k=' + chaves.publica, TTL: '86400', Urgency: 'high' }
        });
        if (r.status === 404 || r.status === 410) remover.push(s.id);
        else if (r.ok) enviadas++;
      } catch (e) { /* ignora falhas individuais */ }
    }));
    for (const id of remover) await env.DB.prepare(`DELETE FROM push_inscricoes WHERE id=?`).bind(id).run();
    const proximo = (desloc + LOTE < total) ? desloc + LOTE - remover.length : null;
    return json({ total, enviadas, proximo });
  }
  return erro('Rota inválida.', 404);
}

// Avisos: os pais só veem os avisos do dia (ou até a data escolhida pelo clube, ex.: dia sem aula).
let colunaExibirAteGarantida = false;
async function garantirColunaExibirAte(env) {
  if (colunaExibirAteGarantida) return;
  const { results } = await env.DB.prepare(`SELECT name FROM pragma_table_info('avisos_publicados')`).all();
  if (!results.some(r => r.name === 'exibir_ate')) {
    try { await env.DB.prepare(`ALTER TABLE avisos_publicados ADD COLUMN exibir_ate TEXT`).run(); } catch (e) {}
  }
  if (!results.some(r => r.name === 'publico')) {
    try { await env.DB.prepare(`ALTER TABLE avisos_publicados ADD COLUMN publico TEXT`).run(); } catch (e) {}
  }
  colunaExibirAteGarantida = true;
}
function hojeRecife() {
  return new Date(Date.now() - 3 * 3600 * 1000).toISOString().slice(0, 10);
}
// avisos antigos (sem data) valem só no dia em que foram criados (fuso de Recife)
const SQL_AVISO_VISIVEL = `(exibir_ate >= ? OR (exibir_ate IS NULL AND substr(datetime(criado_em, '-3 hours'), 1, 10) = ?))`;

// Público do aviso: todos | pais | interno | diretoria
//  - todos: todos os perfis
//  - pais: pais (usuario), diretoria, admin e financeiro
//  - interno: diretoria, técnica, admin e financeiro
//  - diretoria: diretoria, admin e financeiro
// admin e financeiro veem tudo.
function publicosVisiveis(papel) {
  if (papel === 'admin' || papel === 'financeiro' || papel === 'diretoria') return null; // vê todos os públicos
  if (papel === 'tecnica') return ['todos', 'interno'];
  return ['todos', 'pais'];
}
const PAPEIS_DO_PUBLICO = {
  pais: ['usuario', 'diretoria', 'admin', 'financeiro'],
  interno: ['diretoria', 'tecnica', 'admin', 'financeiro'],
  diretoria: ['diretoria', 'admin', 'financeiro']
};
function filtroAvisos(usuario, gerencia, hoje) {
  const cond = [], binds = [];
  const pubs = publicosVisiveis(usuario.papel);
  if (pubs) {
    cond.push('(publico IS NULL OR publico IN (' + pubs.map(() => '?').join(',') + '))');
    binds.push(...pubs);
  }
  if (!gerencia) { cond.push(SQL_AVISO_VISIVEL); binds.push(hoje, hoje); }
  return { cond, binds };
}

async function tratarAvisos(request, env, usuario, rota, metodo) {
  await garantirColunaExibirAte(env);
  const id = rota[1];
  const gerencia = !exigirGerenciar(usuario);
  const hoje = hojeRecife();
  const f = filtroAvisos(usuario, gerencia, hoje);

  if (metodo === 'GET' && id === 'contagem') {
    const desde = new Date(parseInt(new URL(request.url).searchParams.get('desde'), 10) || 0).toISOString();
    const n = (await env.DB.prepare(
      'SELECT COUNT(*) AS n FROM avisos_publicados WHERE criado_em > ?' + f.cond.map(c => ' AND ' + c).join('')
    ).bind(desde, ...f.binds).all()).results;
    const ultimo = await env.DB.prepare(
      'SELECT titulo, criado_em FROM avisos_publicados' + (f.cond.length ? ' WHERE ' + f.cond.join(' AND ') : '') + ' ORDER BY criado_em DESC LIMIT 1'
    ).bind(...f.binds).first();
    return json({ novos: n[0]?.n || 0, ultimo: ultimo || null });
  }
  if (metodo === 'GET' && !id) {
    const { results } = await env.DB.prepare(
      'SELECT * FROM avisos_publicados' + (f.cond.length ? ' WHERE ' + f.cond.join(' AND ') : '') + ' ORDER BY criado_em DESC'
    ).bind(...f.binds).all();
    return json({ avisos: results });
  }
  if (metodo === 'POST' && !id) {
    const bloqueado = exigirGerenciar(usuario);
    if (bloqueado) return bloqueado;
    const c = await request.json();
    if (!c.imagem) return erro('Banner ausente.');
    let ate = /^\d{4}-\d{2}-\d{2}$/.test(c.exibir_ate || '') ? c.exibir_ate : hoje;
    if (ate < hoje) ate = hoje;
    const publico = ['todos', 'pais', 'interno', 'diretoria'].includes(c.publico) ? c.publico : 'todos';
    const novoId = gerarId('av');
    const agora = new Date().toISOString();
    await env.DB.prepare(`INSERT INTO avisos_publicados (id, tipo, titulo, imagem, criado_em, exibir_ate, publico) VALUES (?,?,?,?,?,?,?)`)
      .bind(novoId, c.tipo || 'geral', c.titulo || 'Aviso', c.imagem, agora, ate, publico).run();
    return json({ id: novoId });
  }
  if (metodo === 'PUT' && id) {
    const bloqueado = exigirGerenciar(usuario);
    if (bloqueado) return bloqueado;
    const c = await request.json();
    const titulo = String(c.titulo || '').trim();
    if (!titulo) return erro('Informe o título do aviso.');
    const publico = ['todos', 'pais', 'interno', 'diretoria'].indexOf(c.publico) >= 0 ? c.publico : 'todos';
    const exibirAte = c.exibir_ate || null;
    await env.DB.prepare(`UPDATE avisos_publicados SET titulo=?, exibir_ate=?, publico=? WHERE id=?`).bind(titulo, exibirAte, publico, id).run();
    return json({ ok: true });
  }
  if (metodo === 'DELETE' && id) {
    const bloqueado = exigirGerenciar(usuario);
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
    const papeisValidos = ['admin', 'tecnica', 'diretoria', 'financeiro', 'usuario'];
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

// ---------------------------------------------------------------------------
// FINANCEIRO — Mensalidades, Taxas e Cobranças, Despesas
// Leitura e escrita liberadas apenas para admin e para o papel "financeiro"
// (exigirFinanceiro) — ninguém mais enxerga esse menu.
// ---------------------------------------------------------------------------
function statusMensalidade(m, hojeISO) {
  if (m.data_pagamento) return 'pago';
  if (m.vencimento < hojeISO) return 'inadimplente';
  return 'a_vencer';
}
function diasAtraso(m, hojeISO) {
  if (m.data_pagamento || m.vencimento >= hojeISO) return 0;
  const umDia = 1000 * 60 * 60 * 24;
  return Math.round((new Date(hojeISO) - new Date(m.vencimento)) / umDia);
}

// Garante (uma vez por instância) a coluna de observação em atletas, usada em "Valores de Mensalidade"
let colunaObsMensalidadeGarantida = false;
async function garantirColunaObsMensalidade(env) {
  if (colunaObsMensalidadeGarantida) return;
  const { results } = await env.DB.prepare(`SELECT name FROM pragma_table_info('atletas')`).all();
  if (!results.some(r => r.name === 'observacao_mensalidade')) {
    try {
      await env.DB.prepare(`ALTER TABLE atletas ADD COLUMN observacao_mensalidade TEXT`).run();
    } catch (e) { /* outra requisição pode ter criado a coluna ao mesmo tempo */ }
  }
  colunaObsMensalidadeGarantida = true;
}

async function tratarMensalidades(request, env, usuario, rota, metodo) {
  await garantirColunaObsMensalidade(env);
  const bloqueado = exigirFinanceiro(usuario);
  if (bloqueado) return bloqueado;
  const id = rota[1];
  const hojeISO = new Date().toISOString().slice(0, 10);

  if (metodo === 'GET' && !id) {
    const { results } = await env.DB.prepare(
      `SELECT m.*, a.nome as atleta_nome, a.responsavel, a.telefone
       FROM mensalidades m LEFT JOIN atletas a ON a.id = m.atleta_id
       ORDER BY m.mes_referencia DESC, a.nome`
    ).all();
    const comStatus = results.map(m => ({
      ...m,
      status: statusMensalidade(m, hojeISO),
      diasAtraso: diasAtraso(m, hojeISO)
    }));
    return json({ mensalidades: comStatus });
  }
  if (metodo === 'POST' && id === 'gerar-ano') {
    const c = await request.json();
    const ano = parseInt(c.ano);
    const diaVencimento = parseInt(c.diaVencimento) || 10;
    const desconto = !!c.desconto;
    if (!ano) return erro('Informe o ano.');

    // pega todas as atletas que já têm um valor de mensalidade definido
    const { results: atletas } = await env.DB.prepare(
      `SELECT id, valor_mensalidade, observacao_mensalidade FROM atletas WHERE valor_mensalidade IS NOT NULL AND valor_mensalidade > 0`
    ).all();
    if (atletas.length === 0) return erro('Nenhuma atleta tem valor de mensalidade definido ainda. Preencha em "Valores de Mensalidade" antes de lançar em massa.');

    // já existentes, pra não duplicar
    const { results: existentes } = await env.DB.prepare(
      `SELECT atleta_id, mes_referencia FROM mensalidades WHERE mes_referencia LIKE ?`
    ).bind(ano + '-%').all();
    const jaLancados = new Set(existentes.map(e => e.atleta_id + '|' + e.mes_referencia));

    let criadas = 0, ignoradas = 0;
    for (const a of atletas) {
      const valorBase = a.valor_mensalidade;
      const valorFinal = desconto ? Math.round(valorBase * 0.9 * 100) / 100 : valorBase;
      for (let mes = 1; mes <= 12; mes++) {
        const mesReferencia = ano + '-' + String(mes).padStart(2, '0');
        if (jaLancados.has(a.id + '|' + mesReferencia)) { ignoradas++; continue; }
        const vencimento = mesReferencia + '-' + String(diaVencimento).padStart(2, '0');
        const novoId = gerarId('mn');
        await env.DB.prepare(
          `INSERT INTO mensalidades (id, atleta_id, mes_referencia, valor, vencimento, data_pagamento, valor_pago, observacao, desconto_aplicado) VALUES (?,?,?,?,?,NULL,NULL,?,?)`
        ).bind(novoId, a.id, mesReferencia, valorFinal, vencimento, a.observacao_mensalidade || null, desconto ? 1 : 0).run();
        criadas++;
      }
    }
    return json({ criadas, ignoradas });
  }
  if (metodo === 'POST' && !id) {
    const c = await request.json();
    if (!c.atletaId || !c.mesReferencia || !c.valor || !c.vencimento) return erro('Preencha atleta, mês, valor e vencimento.');
    const valorFinal = c.desconto ? Math.round(c.valor * 0.9 * 100) / 100 : c.valor;
    const novoId = gerarId('mn');
    await env.DB.prepare(
      `INSERT INTO mensalidades (id, atleta_id, mes_referencia, valor, vencimento, data_pagamento, valor_pago, observacao, desconto_aplicado) VALUES (?,?,?,?,?,NULL,NULL,?,?)`
    ).bind(novoId, c.atletaId, c.mesReferencia, valorFinal, c.vencimento, c.observacao || null, c.desconto ? 1 : 0).run();
    return json({ id: novoId });
  }
  if (metodo === 'PUT' && id) {
    const c = await request.json();
    // Edição dos dados da mensalidade (vencimento, valor, observação)
    if (c.vencimento !== undefined) {
      if (!/^\d{4}-\d{2}-\d{2}$/.test(c.vencimento || '')) return erro('Informe um vencimento válido.');
      const valorNovo = parseFloat(c.valor);
      if (!(valorNovo > 0)) return erro('Informe um valor válido.');
      await env.DB.prepare(
        `UPDATE mensalidades SET vencimento=?, valor=?, observacao=? WHERE id=?`
      ).bind(c.vencimento, valorNovo, (c.observacao || '').trim() || null, id).run();
      return json({ ok: true });
    }
    await env.DB.prepare(
      `UPDATE mensalidades SET data_pagamento=?, valor_pago=? WHERE id=?`
    ).bind(c.dataPagamento || null, c.valorPago || null, id).run();
    return json({ ok: true });
  }
  if (metodo === 'DELETE' && id) {
    await env.DB.prepare(`DELETE FROM mensalidades WHERE id=?`).bind(id).run();
    return json({ ok: true });
  }
  return erro('Rota inválida.', 404);
}

// ---------------------------------------------------------------------------
// VALORES DE MENSALIDADE — cadastro: nome, responsável, setor + valor em branco
// para o financeiro preencher individualmente (usado no lançamento em massa)
// ---------------------------------------------------------------------------
async function tratarValoresMensalidade(request, env, usuario, rota, metodo) {
  await garantirColunaObsMensalidade(env);
  const bloqueado = exigirFinanceiro(usuario);
  if (bloqueado) return bloqueado;
  const atletaId = rota[1];

  if (metodo === 'GET' && !atletaId) {
    const { results } = await env.DB.prepare(
      `SELECT id, nome, responsavel, setor, valor_mensalidade, observacao_mensalidade FROM atletas ORDER BY nome`
    ).all();
    return json({ atletas: results });
  }
  if (metodo === 'PUT' && atletaId) {
    const c = await request.json();
    const valor = (c.valor === null || c.valor === '' || c.valor === undefined) ? null : parseFloat(c.valor);
    if (c.observacao !== undefined) {
      await env.DB.prepare(`UPDATE atletas SET valor_mensalidade=?, observacao_mensalidade=? WHERE id=?`)
        .bind(valor, (c.observacao || '').trim() || null, atletaId).run();
    } else {
      await env.DB.prepare(`UPDATE atletas SET valor_mensalidade=? WHERE id=?`).bind(valor, atletaId).run();
    }
    return json({ ok: true });
  }
  return erro('Rota inválida.', 404);
}

let tabelaChamadasGarantida = false;
async function garantirTabelaChamadas(env) {
  if (tabelaChamadasGarantida) return;
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS chamadas (
    id TEXT PRIMARY KEY,
    atleta_id TEXT NOT NULL,
    data TEXT NOT NULL,
    status TEXT NOT NULL,
    registrado_por TEXT,
    criado_em TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (atleta_id, data)
  )`).run();
  tabelaChamadasGarantida = true;
}

// Chamada: técnica, admin e financeiro registram; diretoria só consulta.
async function tratarChamada(request, env, usuario, rota, metodo) {
  if (usuario.papel === 'usuario') return erro('Sem acesso à chamada.', 403);
  await garantirTabelaChamadas(env);
  const url = new URL(request.url);
  const dataOk = (d) => /^\d{4}-\d{2}-\d{2}$/.test(d || '');

  // GET /api/chamada?data=AAAA-MM-DD  -> atletas + faltas já registradas no dia
  if (metodo === 'GET' && !rota[1]) {
    const data = url.searchParams.get('data');
    if (!dataOk(data)) return erro('Data inválida.', 400);
    const { results: atletas } = await env.DB.prepare(
      `SELECT id, nome, setor, categoria FROM atletas ORDER BY nome`
    ).all();
    const { results: regs } = await env.DB.prepare(
      `SELECT atleta_id, status FROM chamadas WHERE data = ?`
    ).bind(data).all();
    const mapa = {};
    regs.forEach(r => { mapa[r.atleta_id] = r.status; });
    return json({ data, atletas: atletas.map(a => ({ ...a, status: mapa[a.id] || null })) });
  }

  // GET /api/chamada/relatorio?de=&ate=  -> frequência por atleta no período
  if (metodo === 'GET' && rota[1] === 'relatorio') {
    const de = url.searchParams.get('de');
    const ate = url.searchParams.get('ate');
    if (!dataOk(de) || !dataOk(ate)) return erro('Período inválido.', 400);
    const { results } = await env.DB.prepare(
      `SELECT a.id, a.nome, a.setor, a.categoria,
              SUM(CASE WHEN c.status = 'P' THEN 1 ELSE 0 END) AS presencas,
              SUM(CASE WHEN c.status = 'F' THEN 1 ELSE 0 END) AS faltas
         FROM atletas a
         LEFT JOIN chamadas c ON c.atleta_id = a.id AND c.data >= ? AND c.data <= ?
        GROUP BY a.id ORDER BY a.nome`
    ).bind(de, ate).all();
    const { results: dias } = await env.DB.prepare(
      `SELECT COUNT(DISTINCT data) AS n FROM chamadas WHERE data >= ? AND data <= ?`
    ).bind(de, ate).all();
    return json({ de, ate, aulas: dias[0]?.n || 0, atletas: results });
  }

  // PUT /api/chamada  { data, atletas:[ids exibidos], faltas:[ids ausentes] }
  if (metodo === 'PUT' && !rota[1]) {
    if (usuario.papel !== 'admin' && usuario.papel !== 'tecnica' && usuario.papel !== 'financeiro') {
      return erro('Você só pode consultar a chamada.', 403);
    }
    const c = await request.json();
    if (!dataOk(c.data) || !Array.isArray(c.atletas) || !Array.isArray(c.faltas)) return erro('Dados inválidos.', 400);
    const faltas = new Set(c.faltas);
    const stmts = c.atletas.map(id =>
      env.DB.prepare(
        `INSERT INTO chamadas (id, atleta_id, data, status, registrado_por) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(atleta_id, data) DO UPDATE SET status = excluded.status, registrado_por = excluded.registrado_por`
      ).bind(crypto.randomUUID(), id, c.data, faltas.has(id) ? 'F' : 'P', usuario.nome || usuario.email || usuario.id || null)
    );
    for (let i = 0; i < stmts.length; i += 50) await env.DB.batch(stmts.slice(i, i + 50));
    return json({ ok: true, registradas: stmts.length, faltas: c.atletas.filter(id => faltas.has(id)).length });
  }
  return erro('Rota inválida.', 404);
}

async function tratarTaxas(request, env, usuario, rota, metodo) {
  const bloqueado = exigirFinanceiro(usuario);
  if (bloqueado) return bloqueado;
  const id = rota[1];

  if (metodo === 'GET' && !id) {
    const { results } = await env.DB.prepare(
      `SELECT t.*, a.nome as atleta_nome FROM taxas t LEFT JOIN atletas a ON a.id = t.atleta_id ORDER BY t.status, t.vencimento`
    ).all();
    return json({ taxas: results });
  }
  if (metodo === 'POST' && !id) {
    const c = await request.json();
    if (!c.tipo || !c.valor) return erro('Informe o tipo e o valor.');
    const novoId = gerarId('tx');
    await env.DB.prepare(
      `INSERT INTO taxas (id, atleta_id, tipo, descricao, valor, vencimento, data_pagamento, status) VALUES (?,?,?,?,?,?,NULL,'pendente')`
    ).bind(novoId, c.atletaId || null, c.tipo, c.descricao || null, c.valor, c.vencimento || null).run();
    return json({ id: novoId });
  }
  if (metodo === 'PATCH' && id) {
    const atual = await env.DB.prepare(`SELECT status FROM taxas WHERE id=?`).bind(id).first();
    if (!atual) return erro('Taxa não encontrada.', 404);
    const novoStatus = atual.status === 'pago' ? 'pendente' : 'pago';
    const dataPagamento = novoStatus === 'pago' ? new Date().toISOString().slice(0, 10) : null;
    await env.DB.prepare(`UPDATE taxas SET status=?, data_pagamento=? WHERE id=?`).bind(novoStatus, dataPagamento, id).run();
    return json({ status: novoStatus });
  }
  if (metodo === 'DELETE' && id) {
    await env.DB.prepare(`DELETE FROM taxas WHERE id=?`).bind(id).run();
    return json({ ok: true });
  }
  return erro('Rota inválida.', 404);
}

async function tratarDespesas(request, env, usuario, rota, metodo) {
  const bloqueado = exigirFinanceiro(usuario);
  if (bloqueado) return bloqueado;
  const id = rota[1];

  if (metodo === 'GET' && !id) {
    const { results } = await env.DB.prepare(`SELECT * FROM despesas ORDER BY data DESC`).all();
    return json({ despesas: results });
  }
  if (metodo === 'POST' && !id) {
    const c = await request.json();
    if (!c.descricao || !c.categoria || !c.valor || !c.data) return erro('Preencha descrição, categoria, valor e data.');
    const novoId = gerarId('ds');
    await env.DB.prepare(
      `INSERT INTO despesas (id, descricao, categoria, valor, data, rateado_atletas, centro_custo) VALUES (?,?,?,?,?,?,?)`
    ).bind(novoId, c.descricao.trim(), c.categoria, c.valor, c.data, c.rateado ? 1 : 0, c.centroCusto || null).run();
    return json({ id: novoId });
  }
  if (metodo === 'DELETE' && id) {
    await env.DB.prepare(`DELETE FROM despesas WHERE id=?`).bind(id).run();
    return json({ ok: true });
  }
  return erro('Rota inválida.', 404);
}

async function tratarFinanceiroResumo(env, usuario) {
  const bloqueado = exigirFinanceiro(usuario);
  if (bloqueado) return bloqueado;
  const hojeISO = new Date().toISOString().slice(0, 10);

  const { results: mensalidades } = await env.DB.prepare(`SELECT * FROM mensalidades`).all();
  const inadimplentes = mensalidades.filter(m => statusMensalidade(m, hojeISO) === 'inadimplente');
  const recebidoMensalidades = mensalidades.filter(m => m.data_pagamento).reduce((s, m) => s + (m.valor_pago || m.valor), 0);
  const emAtrasoValor = inadimplentes.reduce((s, m) => s + m.valor, 0);
  const atletasInadimplentesUnicos = new Set(inadimplentes.map(m => m.atleta_id)).size;

  const { results: taxas } = await env.DB.prepare(`SELECT * FROM taxas`).all();
  const taxasPendentes = taxas.filter(t => t.status === 'pendente');
  const recebidoTaxas = taxas.filter(t => t.status === 'pago').reduce((s, t) => s + t.valor, 0);

  const { results: despesas } = await env.DB.prepare(`SELECT * FROM despesas`).all();
  const totalDespesas = despesas.reduce((s, d) => s + d.valor, 0);

  const totalReceitas = recebidoMensalidades + recebidoTaxas;
  const saldo = totalReceitas - totalDespesas;

  return json({
    totalReceitas, totalDespesas, saldo,
    recebidoMensalidades, recebidoTaxas,
    atletasInadimplentesUnicos,
    parcelasInadimplentes: inadimplentes.length,
    valorEmAtraso: emAtrasoValor,
    taxasPendentesQtd: taxasPendentes.length,
    taxasPendentesValor: taxasPendentes.reduce((s, t) => s + t.valor, 0)
  });
}
