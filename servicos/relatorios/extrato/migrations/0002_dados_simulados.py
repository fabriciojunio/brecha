"""Os mesmos três clientes da API principal, e alguns lançamentos. Dados
simulados: os CPFs são números válidos de exemplo, de ninguém."""

import datetime

from django.db import migrations

CLIENTES = [
    (1, "Ana Souza", "ana@exemplo.com.br", "529.982.247-25", 100),
    (2, "Bruno Lima", "bruno@exemplo.com.br", "111.444.777-35", 200),
    (3, "Operação", "operacao@exemplo.com.br", "390.533.447-05", 300),
]

LANCAMENTOS = [
    (100, datetime.date(2026, 10, 1), "Salário de outubro", 520_000),
    (100, datetime.date(2026, 10, 5), "Aluguel", -180_000),
    (200, datetime.date(2026, 10, 2), "Venda de bicicleta", 95_000),
    (200, datetime.date(2026, 10, 8), "Mercado", -32_000),
]


def criar(apps, _schema):
    cliente = apps.get_model("extrato", "Cliente")
    lancamento = apps.get_model("extrato", "Lancamento")
    for id_, nome, email, cpf, conta in CLIENTES:
        cliente.objects.create(id=id_, nome=nome, email=email, cpf=cpf, conta=conta)
    for conta, data, descricao, valor in LANCAMENTOS:
        lancamento.objects.create(conta=conta, data=data, descricao=descricao, valor_centavos=valor)


def apagar(apps, _schema):
    apps.get_model("extrato", "Lancamento").objects.all().delete()
    apps.get_model("extrato", "Cliente").objects.all().delete()


class Migration(migrations.Migration):
    dependencies = [("extrato", "0001_inicial")]

    operations = [migrations.RunPython(criar, apagar)]
