from django.db import models


class Cliente(models.Model):
    """Cópia do cadastro que o extrato precisa. Dados simulados."""

    id = models.BigIntegerField(primary_key=True)
    nome = models.CharField(max_length=100)
    email = models.CharField(max_length=255)
    cpf = models.CharField(max_length=14)
    conta = models.BigIntegerField(unique=True)


class Lancamento(models.Model):
    conta = models.BigIntegerField(db_index=True)
    data = models.DateField()
    descricao = models.CharField(max_length=140)
    valor_centavos = models.BigIntegerField()

    class Meta:
        ordering = ["data", "id"]
