-- =========================================================
-- AGITA — schema do banco de dados (Cloudflare D1 / SQLite)
-- Rode este arquivo uma vez com:
--   npx wrangler d1 execute agita-db --remote --file=schema.sql
-- =========================================================

DROP TABLE IF EXISTS usuarios;
DROP TABLE IF EXISTS sessoes;
DROP TABLE IF EXISTS atletas;
DROP TABLE IF EXISTS documentos;
DROP TABLE IF EXISTS pagamentos;
DROP TABLE IF EXISTS eventos;
DROP TABLE IF EXISTS avisos_publicados;

CREATE TABLE usuarios (
  id TEXT PRIMARY KEY,
  usuario TEXT NOT NULL UNIQUE,
  senha_hash TEXT NOT NULL,
  senha_salt TEXT NOT NULL,
  nome TEXT NOT NULL,
  papel TEXT NOT NULL CHECK(papel IN ('admin','usuario')),
  precisa_trocar_senha INTEGER NOT NULL DEFAULT 1,
  ultimo_acesso TEXT
);

CREATE TABLE sessoes (
  token TEXT PRIMARY KEY,
  usuario_id TEXT NOT NULL,
  criado_em TEXT NOT NULL,
  expira_em TEXT NOT NULL
);

CREATE TABLE atletas (
  id TEXT PRIMARY KEY,
  nome TEXT NOT NULL,
  nascimento TEXT,
  categoria TEXT,
  responsavel TEXT,
  telefone TEXT,
  foto TEXT
);

CREATE TABLE documentos (
  id TEXT PRIMARY KEY,
  atleta_id TEXT NOT NULL,
  tipo TEXT,
  nome_arquivo TEXT,
  conteudo TEXT,
  data_upload TEXT
);

CREATE TABLE pagamentos (
  id TEXT PRIMARY KEY,
  atleta_id TEXT NOT NULL,
  descricao TEXT,
  valor REAL,
  status TEXT NOT NULL CHECK(status IN ('pendente','confirmado'))
);

CREATE TABLE eventos (
  id TEXT PRIMARY KEY,
  titulo TEXT NOT NULL,
  inicio TEXT NOT NULL,
  fim TEXT NOT NULL,
  tipo TEXT
);

CREATE TABLE avisos_publicados (
  id TEXT PRIMARY KEY,
  tipo TEXT,
  titulo TEXT,
  imagem TEXT,
  criado_em TEXT
);

-- Usuário admin inicial — login "admin", senha "Agita@123" (troca obrigatória no 1º acesso)
-- Hash gerado com PBKDF2-HMAC-SHA256, 100000 iterações (mesmo algoritmo usado pela API).
INSERT INTO usuarios (id, usuario, senha_hash, senha_salt, nome, papel, precisa_trocar_senha, ultimo_acesso)
VALUES (
  'u1',
  'admin',
  '974356b8eddf2c71cb7ad672936abd5a52557bd61b94d5c5f67949d0ec316010',
  'ee7fe0280cbc8b8a24520ea05d7f5039',
  'Administrador',
  'admin',
  1,
  NULL
);
