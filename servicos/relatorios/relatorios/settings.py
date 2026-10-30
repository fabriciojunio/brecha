"""Configuração do serviço de relatórios. Tudo que é segredo vem do ambiente.

Vulnerável de propósito no /v1, e só para laboratório local. Dados simulados.
"""

import os


def segredo(nome: str) -> str:
    """Lê do arquivo em NOME_ARQUIVO quando existir (a forma da versão
    corrigida) ou da variável NOME (a do laboratório)."""
    arquivo = os.environ.get(f"{nome}_ARQUIVO")
    if arquivo:
        with open(arquivo, encoding="utf-8") as conteudo:
            return conteudo.read().strip()
    return os.environ.get(nome, "")


def obrigatorio(nome: str) -> str:
    valor = segredo(nome)
    if not valor:
        raise RuntimeError(f"{nome} não definido")
    return valor


SECRET_KEY = obrigatorio("DJANGO_SECRET_KEY")
DEBUG = os.environ.get("DJANGO_DEBUG") == "1"
ALLOWED_HOSTS = [h for h in os.environ.get("DJANGO_ALLOWED_HOSTS", "127.0.0.1,localhost").split(",") if h]

# Segredo do token emitido pela API principal (o mesmo brecha.segredo do /v2)
# e token que a API usa para avisar este serviço de cada transferência.
BRECHA_SEGREDO = obrigatorio("BRECHA_SEGREDO").encode()
TOKEN_DE_SERVICO = obrigatorio("RELATORIOS_TOKEN_DE_SERVICO")

INSTALLED_APPS = ["extrato"]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "relatorios.urls"
WSGI_APPLICATION = "relatorios.wsgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "APP_DIRS": True,
        "OPTIONS": {},
    }
]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "HOST": os.environ.get("PGHOST", "127.0.0.1"),
        "PORT": os.environ.get("PGPORT", "5432"),
        "NAME": os.environ.get("PGDATABASE", "relatorios"),
        "USER": os.environ.get("PGUSER", "relatorios"),
        "PASSWORD": segredo("PGPASSWORD"),
        "CONN_MAX_AGE": 60,
    }
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
USE_TZ = True
TIME_ZONE = "America/Sao_Paulo"
LANGUAGE_CODE = "pt-br"

SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "no-referrer"
X_FRAME_OPTIONS = "DENY"
DATA_UPLOAD_MAX_MEMORY_SIZE = 16 * 1024

LOGGING = {
    "version": 1,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    "root": {"handlers": ["console"], "level": "INFO"},
}
