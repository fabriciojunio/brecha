from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="Cliente",
            fields=[
                ("id", models.BigIntegerField(primary_key=True, serialize=False)),
                ("nome", models.CharField(max_length=100)),
                ("email", models.CharField(max_length=255)),
                ("cpf", models.CharField(max_length=14)),
                ("conta", models.BigIntegerField(unique=True)),
            ],
        ),
        migrations.CreateModel(
            name="Lancamento",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("conta", models.BigIntegerField(db_index=True)),
                ("data", models.DateField()),
                ("descricao", models.CharField(max_length=140)),
                ("valor_centavos", models.BigIntegerField()),
            ],
            options={"ordering": ["data", "id"]},
        ),
    ]
