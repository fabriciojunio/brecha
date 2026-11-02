# Dependências instaladas só se o hash bater (--require-hashes), num venv que
# vai pronto para a imagem final. A imagem final roda sem root e sem pip.
FROM python:3.13.16-slim-trixie@sha256:cf50a4f6ac4f026458b08d5222023d700ac806410dff5e9ca8728fa44f2b850f AS construcao
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
COPY requirements.txt /tmp/requirements.txt
RUN python -m venv /venv && /venv/bin/pip install --require-hashes -r /tmp/requirements.txt

FROM python:3.13.16-slim-trixie@sha256:cf50a4f6ac4f026458b08d5222023d700ac806410dff5e9ca8728fa44f2b850f
ENV PATH=/venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN pip uninstall -y pip setuptools wheel 2>/dev/null; useradd --system --uid 10001 --no-create-home relatorios
COPY --from=construcao /venv /venv
WORKDIR /app
COPY --chown=root:root manage.py ./
COPY --chown=root:root relatorios relatorios
COPY --chown=root:root extrato extrato
USER 10001
EXPOSE 8000
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--access-logfile", "-", "relatorios.wsgi:application"]
